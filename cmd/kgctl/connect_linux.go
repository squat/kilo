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
	"net"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/oklog/run"
	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/squat/kilo/pkg/iproute"
	"github.com/squat/kilo/pkg/k8s/apis/kilo/v1alpha1"
	"github.com/squat/kilo/pkg/mesh"
	"github.com/squat/kilo/pkg/route"
	"github.com/squat/kilo/pkg/wireguard"
)

var (
	logLevel    string
	connectOpts struct {
		allowedIP           net.IPNet
		allowedIPs          []net.IPNet
		privateKey          string
		cleanUp             bool
		mtu                 uint
		resyncPeriod        time.Duration
		interfaceName       string
		persistentKeepalive int
	}
)

func takeIPNet(_ net.IP, i *net.IPNet, err error) *net.IPNet {
	if err != nil {
		panic(err)
	}
	return i
}

func connect() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "connect",
		Args:         cobra.ExactArgs(1),
		RunE:         runConnect,
		Short:        "connect to a Kilo cluster as a peer over WireGuard",
		SilenceUsage: true,
	}
	cmd.Flags().IPNetVarP(&connectOpts.allowedIP, "allowed-ip", "a", *takeIPNet(net.ParseCIDR("10.10.10.10/32")), "Allowed IP of the peer.")
	cmd.Flags().StringSliceVar(&allowedIPs, "allowed-ips", []string{}, "Additional allowed IPs of the cluster, e.g. the service CIDR.")
	cmd.Flags().StringVar(&logLevel, "log-level", logLevelInfo, fmt.Sprintf("Log level to use. Possible values: %s", availableLogLevels))
	cmd.Flags().StringVar(&connectOpts.privateKey, "private-key", "", "Path to an existing WireGuard private key file.")
	cmd.Flags().BoolVar(&connectOpts.cleanUp, "clean-up", true, "Should Kilo clean up the routes and interface when it shuts down?")
	cmd.Flags().UintVar(&connectOpts.mtu, "mtu", uint(1420), "The MTU for the WireGuard interface.")
	cmd.Flags().DurationVar(&connectOpts.resyncPeriod, "resync-period", 30*time.Second, "How often should Kilo reconcile?")
	cmd.Flags().StringVarP(&connectOpts.interfaceName, "interface", "i", mesh.DefaultKiloInterface, "Name of the Kilo interface to use; if it does not exist, it will be created.")
	cmd.Flags().IntVar(&connectOpts.persistentKeepalive, "persistent-keepalive", 10, "How often should WireGuard send keepalives? Setting to 0 will disable sending keepalives.")

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

func runConnect(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := log.NewJSONLogger(log.NewSyncWriter(os.Stdout))
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
	peerName := args[0]

	for i := range allowedIPs {
		_, aip, err := net.ParseCIDR(allowedIPs[i])
		if err != nil {
			return err
		}
		connectOpts.allowedIPs = append(connectOpts.allowedIPs, *aip)
	}

	var privateKey wgtypes.Key
	var err error
	if connectOpts.privateKey == "" {
		privateKey, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			return fmt.Errorf("failed to generate private key: %w", err)
		}
	} else {
		raw, err := os.ReadFile(connectOpts.privateKey)
		if err != nil {
			return fmt.Errorf("failed to read private key: %w", err)
		}
		privateKey, err = wgtypes.ParseKey(string(raw))
		if err != nil {
			return fmt.Errorf("failed to parse private key: %w", err)
		}
	}
	publicKey := privateKey.PublicKey()
	level.Info(logger).Log("msg", "generated public key", "key", publicKey)

	if _, err := opts.kc.KiloV1alpha1().Peers().Get(ctx, peerName, metav1.GetOptions{}); apierrors.IsNotFound(err) {
		peer := &v1alpha1.Peer{
			ObjectMeta: metav1.ObjectMeta{
				Name: peerName,
			},
			Spec: v1alpha1.PeerSpec{
				AllowedIPs:          []string{connectOpts.allowedIP.String()},
				PersistentKeepalive: connectOpts.persistentKeepalive,
				PublicKey:           publicKey.String(),
			},
		}
		if _, err := opts.kc.KiloV1alpha1().Peers().Create(ctx, peer, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("failed to create peer: %w", err)
		}
		level.Info(logger).Log("msg", "created peer", "peer", peerName)
		if connectOpts.cleanUp {
			defer func() {
				ctxWithTimeout, cancelWithTimeout := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancelWithTimeout()
				if err := opts.kc.KiloV1alpha1().Peers().Delete(ctxWithTimeout, peerName, metav1.DeleteOptions{}); err != nil {
					level.Error(logger).Log("err", fmt.Sprintf("failed to delete peer: %v", err))
				} else {
					level.Info(logger).Log("msg", "deleted peer", "peer", peerName)
				}
			}()
		}

	} else if err != nil {
		return fmt.Errorf("failed to get peer: %w", err)
	}

	iface, _, err := wireguard.New(connectOpts.interfaceName, connectOpts.mtu)
	if err != nil {
		return fmt.Errorf("failed to create wg interface: %w", err)
	}
	level.Info(logger).Log("msg", "created WireGuard interface", "name", connectOpts.interfaceName, "index", iface)

	table := route.NewTable()
	if connectOpts.cleanUp {
		defer cleanUp(iface, table, logger)
	}

	if err := iproute.SetAddress(iface, &connectOpts.allowedIP); err != nil {
		return err
	}
	level.Info(logger).Log("msg", "set IP address of WireGuard interface", "IP", connectOpts.allowedIP.String())

	if err := iproute.Set(iface, true); err != nil {
		return err
	}

	var g run.Group
	g.Add(run.SignalHandler(ctx, syscall.SIGINT, syscall.SIGTERM))

	{
		g.Add(
			func() error {
				errCh, err := table.Run(ctx.Done())
				if err != nil {
					return fmt.Errorf("failed to watch for route table updates: %w", err)
				}
				for {
					select {
					case err, ok := <-errCh:
						if ok {
							level.Error(logger).Log("err", err.Error())
						} else {
							return nil
						}
					case <-ctx.Done():
						return nil
					}
				}
			},
			func(err error) {
				cancel()
				var serr run.SignalError
				if ok := errors.As(err, &serr); ok {
					level.Debug(logger).Log("msg", "received signal", "signal", serr.Signal.String(), "err", err.Error())
				} else {
					level.Error(logger).Log("msg", "received error", "err", err.Error())
				}
			},
		)
	}
	{
		g.Add(
			func() error {
				level.Info(logger).Log("msg", "starting syncer")
				for {
					if err := sync(table, peerName, privateKey, iface, logger); err != nil {
						level.Error(logger).Log("msg", "failed to sync", "err", err.Error())
					}
					select {
					case <-time.After(connectOpts.resyncPeriod):
					case <-ctx.Done():
						return nil
					}
				}
			}, func(err error) {
				cancel()
				var serr run.SignalError
				if ok := errors.As(err, &serr); ok {
					level.Debug(logger).Log("msg", "received signal", "signal", serr.Signal.String(), "err", err.Error())
				} else {
					level.Error(logger).Log("msg", "received error", "err", err.Error())
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

func cleanUp(iface int, t *route.Table, logger log.Logger) {
	if err := iproute.Set(iface, false); err != nil {
		level.Error(logger).Log("err", fmt.Sprintf("failed to set WireGuard interface down: %v", err))
	}
	if err := iproute.RemoveInterface(iface); err != nil {
		level.Error(logger).Log("err", fmt.Sprintf("failed to remove WireGuard interface: %v", err))
	}
	if err := t.CleanUp(); err != nil {
		level.Error(logger).Log("failed to clean up routes: %v", err)
	}

	return
}

func sync(table *route.Table, peerName string, privateKey wgtypes.Key, iface int, logger log.Logger) error {
	ns, err := opts.backend.Nodes().List()
	if err != nil {
		return fmt.Errorf("failed to list nodes: %w", err)
	}
	for _, n := range ns {
		_, err := n.Endpoint.UDPAddr(true)
		if err != nil {
			return err
		}
	}
	ps, err := opts.backend.Peers().List()
	if err != nil {
		return fmt.Errorf("failed to list peers: %w", err)
	}
	// Obtain the Granularity by looking at the annotation of the first node.
	if opts.granularity, err = determineGranularity(opts.granularity, ns); err != nil {
		return fmt.Errorf("failed to determine granularity: %w", err)
	}
	var hostname string
	var subnet *net.IPNet
	nodes := make(map[string]*mesh.Node)
	var nodeNames []string
	for _, n := range ns {
		if n.Ready() {
			nodes[n.Name] = n
			hostname = n.Name
			nodeNames = append(nodeNames, n.Name)
		}
		if n.WireGuardIP != nil && subnet == nil {
			subnet = n.WireGuardIP
		}
	}
	if len(nodes) == 0 {
		return errors.New("did not find any valid Kilo nodes in the cluster")
	}
	if subnet == nil {
		return errors.New("did not find a valid Kilo subnet on any node")
	}
	subnet.IP = subnet.IP.Mask(subnet.Mask)
	sort.Strings(nodeNames)
	nodes[nodeNames[0]].AllowedLocationIPs = append(nodes[nodeNames[0]].AllowedLocationIPs, connectOpts.allowedIPs...)
	peers := make(map[string]*mesh.Peer)
	for _, p := range ps {
		if p.Ready() {
			peers[p.Name] = p
		}
	}
	if _, ok := peers[peerName]; !ok {
		return fmt.Errorf("did not find any peer named %q in the cluster", peerName)
	}

	t, err := mesh.NewTopology(nodes, peers, opts.granularity, hostname, opts.port, wgtypes.Key{}, subnet, *peers[peerName].PersistentKeepaliveInterval, logger)
	if err != nil {
		return fmt.Errorf("failed to create topology: %w", err)
	}
	conf := t.PeerConf(peerName)
	conf.PrivateKey = &privateKey
	conf.ListenPort = &opts.port

	wgClient, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer wgClient.Close()

	current, err := wgClient.Device(connectOpts.interfaceName)
	if err != nil {
		return err
	}

	var equal bool
	var diff string
	equal, diff = conf.Equal(current)
	if !equal {
		// If the key is empty, then it's the first time we are running
		// so don't bother printing a diff.
		if current.PrivateKey != [wgtypes.KeyLen]byte{} {
			level.Info(logger).Log("msg", "WireGuard configurations are different", "diff", diff)
		}
		level.Debug(logger).Log("msg", "setting WireGuard config", "config", conf.WGConfig())
		if err := wgClient.ConfigureDevice(connectOpts.interfaceName, conf.WGConfig()); err != nil {
			return err
		}
	}

	if err := table.Set(t.PeerRoutes(peerName, iface, connectOpts.allowedIPs)); err != nil {
		return fmt.Errorf("failed to update route table: %w", err)
	}

	return nil
}
