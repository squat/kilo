// Copyright 2022 the Kilo authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux
// +build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	logg "log"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/oklog/run"
	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/squat/kilo/pkg/iproute"
	"github.com/squat/kilo/pkg/k8s"
	"github.com/squat/kilo/pkg/k8s/apis/kilo/v1alpha1"
	kiloclient "github.com/squat/kilo/pkg/k8s/clientset/versioned"
	"github.com/squat/kilo/pkg/mesh"
	"github.com/squat/kilo/pkg/route"
	"github.com/squat/kilo/pkg/wireguard"
)

func takeIPNet(_ net.IP, i *net.IPNet, _ error) *net.IPNet {
	return i
}

func connect() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "connect",
		Args:  cobra.MaximumNArgs(1),
		RunE:  connectAsPeer,
		Short: "connect to a Kilo cluster as a peer over WireGuard",
	}
	cmd.Flags().IPNetP("allowed-ip", "a", *takeIPNet(net.ParseCIDR("10.10.10.10/32")), "Allowed IP of the peer")
	cmd.Flags().IPNetP("service-cidr", "c", *takeIPNet(net.ParseCIDR("10.43.0.0/16")), "service CIDR of the cluster")
	cmd.Flags().String("log-level", logLevelInfo, fmt.Sprintf("Log level to use. Possible values: %s", availableLogLevels))
	cmd.Flags().String("config-path", "/tmp/wg.ini", "path to WireGuard configuation file")
	cmd.Flags().Bool("clean-up", true, "clean up routes and interface")
	cmd.Flags().Uint("mtu", uint(1420), "clean up routes and interface")
	cmd.Flags().Duration("resync-period", 30*time.Second, "How often should Kilo reconcile?")

	availableLogLevels = strings.Join([]string{
		logLevelAll,
		logLevelDebug,
		logLevelInfo,
		logLevelWarn,
		logLevelError,
		logLevelNone,
	}, ", ")

	return cmd
}

func connectAsPeer(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resyncPersiod, err := cmd.Flags().GetDuration("resync-period")
	if err != nil {
		return err
	}
	mtu, err := cmd.Flags().GetUint("mtu")
	if err != nil {
		return err
	}
	configPath, err := cmd.Flags().GetString("config-path")
	if err != nil {
		return err
	}
	serviceCIDR, err := cmd.Flags().GetIPNet("service-cidr")
	if err != nil {
		return err
	}
	allowedIP, err := cmd.Flags().GetIPNet("allowed-ip")
	if err != nil {
		return err
	}
	logger := log.NewJSONLogger(log.NewSyncWriter(os.Stdout))
	logLevel, err := cmd.Flags().GetString("log-level")
	if err != nil {
		return err
	}
	switch logLevel {
	case logLevelAll:
		logger = level.NewFilter(logger, level.AllowAll())
	case logLevelDebug:
		logger = level.NewFilter(logger, level.AllowDebug())
	case logLevelInfo:
		logger = level.NewFilter(logger, level.AllowInfo())
	case logLevelWarn:
		logger = level.NewFilter(logger, level.AllowWarn())
	case logLevelError:
		logger = level.NewFilter(logger, level.AllowError())
	case logLevelNone:
		logger = level.NewFilter(logger, level.AllowNone())
	default:
		return fmt.Errorf("log level %s unknown; possible values are: %s", logLevel, availableLogLevels)
	}
	logger = log.With(logger, "ts", log.DefaultTimestampUTC)
	logger = log.With(logger, "caller", log.DefaultCaller)
	peername := "random"
	if len(args) == 1 {
		peername = args[0]
	}

	var kiloClient *kiloclient.Clientset
	switch backend {
	case k8s.Backend:
		config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return fmt.Errorf("failed to create Kubernetes config: %v", err)
		}
		kiloClient = kiloclient.NewForConfigOrDie(config)
	default:
		return fmt.Errorf("backend %v unknown; posible values are: %s", backend, availableBackends)
	}
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}
	publicKey := privateKey.PublicKey()
	level.Info(logger).Log("msg", "generated public key", "key", publicKey)

	peer := &v1alpha1.Peer{
		ObjectMeta: metav1.ObjectMeta{
			Name: peername,
		},
		Spec: v1alpha1.PeerSpec{
			AllowedIPs:          []string{allowedIP.String()},
			PersistentKeepalive: 10,
			PublicKey:           publicKey.String(),
		},
	}
	if p, err := kiloClient.KiloV1alpha1().Peers().Get(ctx, peername, metav1.GetOptions{}); err != nil || p == nil {
		peer, err = kiloClient.KiloV1alpha1().Peers().Create(ctx, peer, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed to create peer: %w", err)
		}
	}

	kiloIfaceName := "kilo0"

	iface, _, err := wireguard.New(kiloIfaceName, mtu)
	if err != nil {
		return fmt.Errorf("failed to create wg interface: %w", err)
	}
	level.Info(logger).Log("msg", "successfully created wg interface", "name", kiloIfaceName, "no", iface)
	if err := iproute.Set(iface, false); err != nil {
		return err
	}

	if err := iproute.SetAddress(iface, &allowedIP); err != nil {
		return err
	}
	level.Info(logger).Log("mag", "successfully set IP address of wg interface", "IP", allowedIP.String())

	if err := iproute.Set(iface, true); err != nil {
		return err
	}

	var g run.Group
	g.Add(run.SignalHandler(ctx, syscall.SIGINT, syscall.SIGTERM))

	table := route.NewTable()
	stop := make(chan struct{}, 1)
	errCh := make(<-chan error, 1)
	{
		ch := make(chan struct{}, 1)
		g.Add(
			func() error {
				for {
					select {
					case err, ok := <-errCh:
						if ok {
							level.Error(logger).Log("err", err.Error())
						} else {
							return nil
						}
					case <-ch:
						return nil
					}
				}
			},
			func(err error) {
				ch <- struct{}{}
				close(ch)
				stop <- struct{}{}
				close(stop)
				level.Error(logger).Log("msg", "stopped ip routes table", "err", err.Error())
			},
		)
	}
	{
		ch := make(chan struct{}, 1)
		g.Add(
			func() error {
				for {
					ns, err := opts.backend.Nodes().List()
					if err != nil {
						return fmt.Errorf("failed to list nodes: %v", err)
					}
					for _, n := range ns {
						_, err := n.Endpoint.UDPAddr(true)
						if err != nil {
							return err
						}
					}
					ps, err := opts.backend.Peers().List()
					if err != nil {
						return fmt.Errorf("failed to list peers: %v", err)
					}
					// Obtain the Granularity by looking at the annotation of the first node.
					if opts.granularity, err = optainGranularity(opts.granularity, ns); err != nil {
						return fmt.Errorf("failed to obtain granularity: %w", err)
					}
					var hostname string
					subnet := mesh.DefaultKiloSubnet
					nodes := make(map[string]*mesh.Node)
					for _, n := range ns {
						if n.Ready() {
							nodes[n.Name] = n
							hostname = n.Name
						}
						if n.WireGuardIP != nil {
							subnet = n.WireGuardIP
						}
					}
					subnet.IP = subnet.IP.Mask(subnet.Mask)
					if len(nodes) == 0 {
						return errors.New("did not find any valid Kilo nodes in the cluster")
					}
					peers := make(map[string]*mesh.Peer)
					for _, p := range ps {
						if p.Ready() {
							peers[p.Name] = p
						}
					}
					if _, ok := peers[peername]; !ok {
						return fmt.Errorf("did not find any peer named %q in the cluster", peername)
					}

					t, err := mesh.NewTopology(nodes, peers, opts.granularity, hostname, opts.port, wgtypes.Key{}, subnet, *peers[peername].PersistentKeepaliveInterval, logger)
					if err != nil {
						return fmt.Errorf("failed to create topology: %v", err)
					}
					conf := t.PeerConf(peername)
					conf.PrivateKey = &privateKey
					port, err := cmd.Flags().GetInt("port")
					if err != nil {
						logg.Fatal(err)
					}
					conf.ListenPort = &port
					buf, err := conf.Bytes()
					if err != nil {
						return err
					}
					if err := ioutil.WriteFile("/tmp/wg.ini", buf, 0o600); err != nil {
						return err
					}
					wgClient, err := wgctrl.New()
					if err != nil {
						return fmt.Errorf("failed to initialize wg Client: %w", err)
					}
					defer wgClient.Close()
					if err := wgClient.ConfigureDevice(kiloIfaceName, conf.WGConfig()); err != nil {
						return err
					}
					wgConf := wgtypes.Config{
						PrivateKey: &privateKey,
					}
					if err := wgClient.ConfigureDevice(kiloIfaceName, wgConf); err != nil {
						return fmt.Errorf("failed to configure wg interface: %w", err)
					}

					var routes []*netlink.Route
					for _, segment := range t.Segments {
						for i := range segment.CIDRS() {
							// Add routes to the Pod CIDRs of nodes in other segments.
							routes = append(routes, &netlink.Route{
								Dst:       segment.CIDRS()[i],
								Flags:     int(netlink.FLAG_ONLINK),
								Gw:        segment.WireGuardIP(),
								LinkIndex: iface,
								Protocol:  unix.RTPROT_STATIC,
							})
						}
						for i := range segment.PrivateIPs() {
							// Add routes to the private IPs of nodes in other segments.
							routes = append(routes, &netlink.Route{
								Dst:       mesh.OneAddressCIDR(segment.PrivateIPs()[i]),
								Flags:     int(netlink.FLAG_ONLINK),
								Gw:        segment.WireGuardIP(),
								LinkIndex: iface,
								Protocol:  unix.RTPROT_STATIC,
							})
						}
						// Add routes for the allowed location IPs of all segments.
						for i := range segment.AllowedLocationIPs() {
							routes = append(routes, &netlink.Route{
								Dst:       &segment.AllowedLocationIPs()[i],
								Flags:     int(netlink.FLAG_ONLINK),
								Gw:        segment.WireGuardIP(),
								LinkIndex: iface,
								Protocol:  unix.RTPROT_STATIC,
							})
						}
						routes = append(routes, &netlink.Route{
							Dst:       mesh.OneAddressCIDR(segment.WireGuardIP()),
							LinkIndex: iface,
							Protocol:  unix.RTPROT_STATIC,
						})
					}
					// Add routes for the allowed IPs of peers.
					for _, peer := range t.Peers() {
						for i := range peer.AllowedIPs {
							routes = append(routes, &netlink.Route{
								Dst:       &peer.AllowedIPs[i],
								LinkIndex: iface,
								Protocol:  unix.RTPROT_STATIC,
							})
						}
					}
					routes = append(routes, &netlink.Route{
						Dst:       &serviceCIDR,
						Flags:     int(netlink.FLAG_ONLINK),
						Gw:        t.Segments[0].WireGuardIP(),
						LinkIndex: iface,
						Protocol:  unix.RTPROT_STATIC,
					})

					level.Debug(logger).Log("routes", routes)
					if err := table.Set(routes, []*netlink.Rule{}); err != nil {
						return fmt.Errorf("failed to set ip routes table: %w", err)
					}
					errCh, err = table.Run(stop)
					if err != nil {
						return fmt.Errorf("failed to start ip routes tables: %w", err)
					}
					select {
					case <-time.After(resyncPersiod):
					case <-ch:
						return nil
					}
				}
			}, func(err error) {
				// Cancel the root context in the very end.
				defer cancel()
				ch <- struct{}{}
				var serr run.SignalError
				if ok := errors.As(err, &serr); ok {
					level.Info(logger).Log("msg", "received signal", "signal", serr.Signal.String(), "err", err.Error())
				} else {
					level.Error(logger).Log("msg", "received error", "err", err.Error())
				}
				level.Debug(logger).Log("msg", "stoped ip routes table")
				ctxWithTimeOut, cancelWithTimeOut := context.WithTimeout(ctx, 10*time.Second)
				defer func() {
					cancelWithTimeOut()
					level.Debug(logger).Log("msg", "canceled timed context")
				}()
				if err := kiloClient.KiloV1alpha1().Peers().Delete(ctxWithTimeOut, peername, metav1.DeleteOptions{}); err != nil {
					level.Error(logger).Log("failed to delete peer: %w", err)
				} else {
					level.Info(logger).Log("msg", "deleted peer", "peer", peername)
				}
				if ok, err := cmd.Flags().GetBool("clean-up"); err != nil {
					level.Error(logger).Log("err", err.Error(), "msg", "failed to get value from clean-up flag")
				} else if ok {
					cleanUp(iface, table, configPath, logger)
				}
			})
	}
	err = g.Run()
	var serr run.SignalError
	if ok := errors.As(err, &serr); ok {
		return nil
	}
	return err
}

func cleanUp(iface int, t *route.Table, configPath string, logger log.Logger) {
	if err := iproute.Set(iface, false); err != nil {
		level.Error(logger).Log("err", err.Error(), "msg", "failed to set down wg interface")
	}
	if err := os.Remove(configPath); err != nil {
		level.Error(logger).Log("error", fmt.Sprintf("failed to delete configuration file: %v", err))
	}
	if err := iproute.RemoveInterface(iface); err != nil {
		level.Error(logger).Log("error", fmt.Sprintf("failed to remove WireGuard interface: %v", err))
	}
	if err := t.CleanUp(); err != nil {
		level.Error(logger).Log("failed to clean up routes: %w", err)
	}
	return
}
