// Copyright 2021 the Kilo authors
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

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/metalmatze/signal/internalserver"
	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/spf13/cobra"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/squat/kilo/pkg/encapsulation"
	"github.com/squat/kilo/pkg/k8s"
	kiloclient "github.com/squat/kilo/pkg/k8s/clientset/versioned"
	"github.com/squat/kilo/pkg/mesh"
	"github.com/squat/kilo/pkg/version"
	"github.com/squat/kilo/pkg/wireguard"
)

const (
	logLevelAll   = "all"
	logLevelDebug = "debug"
	logLevelInfo  = "info"
	logLevelWarn  = "warn"
	logLevelError = "error"
	logLevelNone  = "none"
)

var (
	availableBackends = strings.Join([]string{
		k8s.Backend,
	}, ", ")
	availableCompatibilities = strings.Join([]string{
		"flannel",
	}, ", ")
	availableEncapsulations = strings.Join([]string{
		string(encapsulation.Never),
		string(encapsulation.CrossSubnet),
		string(encapsulation.Always),
	}, ", ")
	availableGranularities = strings.Join([]string{
		string(mesh.LogicalGranularity),
		string(mesh.FullGranularity),
	}, ", ")
	availableLogLevels = strings.Join([]string{
		logLevelAll,
		logLevelDebug,
		logLevelInfo,
		logLevelWarn,
		logLevelError,
		logLevelNone,
	}, ", ")
)

var cmd = &cobra.Command{
	Use:   "kg",
	Short: "kg is the Kilo agent",
	Long: `kg is the Kilo agent.
		It runs on every node of a cluster,
		setting up the public and private keys for the VPN
		as well as the necessary rules to route packets between locations.`,
	PreRunE:       preRun,
	RunE:          runRoot,
	SilenceUsage:  true,
	SilenceErrors: true,
}

var (
	backend               string
	cleanUpIface          bool
	createIface           bool
	cni                   bool
	cniPath               string
	compatibility         string
	encapsulate           string
	granularity           string
	hostname              string
	kubeconfig            string
	iface                 string
	listen                string
	local                 bool
	master                string
	mtu                   uint
	topologyLabel         string
	port                  int
	subnet                string
	resyncPeriod          time.Duration
	iptablesForwardRule   bool
	prioritisePrivateAddr bool
	dropOtherIpIpTraffic  bool

	printVersion bool
	logLevel     string

	logger   log.Logger
	registry *prometheus.Registry
)

func init() {
	cmd.Flags().StringVar(&backend, "backend", k8s.Backend, fmt.Sprintf("The backend for the mesh. Possible values: %s", availableBackends))
	cmd.Flags().BoolVar(&cleanUpIface, "clean-up-interface", false, "Should Kilo delete its interface when it shuts down?")
	cmd.Flags().BoolVar(&createIface, "create-interface", true, "Should kilo create an interface on startup?")
	cmd.Flags().BoolVar(&cni, "cni", true, "Should Kilo manage the node's CNI configuration?")
	cmd.Flags().StringVar(&cniPath, "cni-path", mesh.DefaultCNIPath, "Path to CNI config.")
	cmd.Flags().StringVar(&compatibility, "compatibility", "", fmt.Sprintf("Should Kilo run in compatibility mode? Possible values: %s", availableCompatibilities))
	cmd.Flags().StringVar(&encapsulate, "encapsulate", string(encapsulation.Always), fmt.Sprintf("When should Kilo encapsulate packets within a location? Possible values: %s", availableEncapsulations))
	cmd.Flags().StringVar(&granularity, "mesh-granularity", string(mesh.LogicalGranularity), fmt.Sprintf("The granularity of the network mesh to create. Possible values: %s", availableGranularities))
	cmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig.")
	cmd.Flags().StringVar(&hostname, "hostname", "", "Hostname of the node on which this process is running.")
	cmd.Flags().StringVar(&iface, "interface", mesh.DefaultKiloInterface, "Name of the Kilo interface to use; if it does not exist, it will be created.")
	cmd.Flags().StringVar(&listen, "listen", ":1107", "The address at which to listen for health and metrics.")
	cmd.Flags().BoolVar(&local, "local", true, "Should Kilo manage routes within a location?")
	cmd.Flags().StringVar(&master, "master", "", "The address of the Kubernetes API server (overrides any value in kubeconfig).")
	cmd.Flags().UintVar(&mtu, "mtu", wireguard.DefaultMTU, "The MTU of the WireGuard interface created by Kilo.")
	cmd.Flags().StringVar(&topologyLabel, "topology-label", k8s.RegionLabelKey, "Kubernetes node label used to group nodes into logical locations.")
	cmd.Flags().IntVar(&port, "port", mesh.DefaultKiloPort, "The port over which WireGuard peers should communicate.")
	cmd.Flags().StringVar(&subnet, "subnet", mesh.DefaultKiloSubnet.String(), "CIDR from which to allocate addresses for WireGuard interfaces.")
	cmd.Flags().DurationVar(&resyncPeriod, "resync-period", 30*time.Second, "How often should the Kilo controllers reconcile?")
	cmd.Flags().BoolVar(&iptablesForwardRule, "iptables-forward-rules", false, "Add default accept rules to the FORWARD chain in iptables. Warning: this may break firewalls with a deny all policy and is potentially insecure!")
	cmd.Flags().BoolVar(&prioritisePrivateAddr, "prioritise-private-addresses", false, "Prefer to assign a private IP address to the node's endpoint.")
	cmd.Flags().BoolVar(&dropOtherIpIpTraffic, "drop-other-ipip-traffic", true, "Should Kilo drop other IP-over-IP traffic (not available in compatibility mode)?")

	cmd.PersistentFlags().BoolVar(&printVersion, "version", false, "Print version and exit")
	cmd.PersistentFlags().StringVar(&logLevel, "log-level", logLevelInfo, fmt.Sprintf("Log level to use. Possible values: %s", availableLogLevels))
}

func preRun(_ *cobra.Command, _ []string) error {
	logger = log.NewJSONLogger(log.NewSyncWriter(os.Stdout))
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
		return fmt.Errorf("log level %v unknown; possible values are: %s", logLevel, availableLogLevels)
	}
	logger = log.With(logger, "ts", log.DefaultTimestampUTC)
	logger = log.With(logger, "caller", log.DefaultCaller)

	registry = prometheus.NewRegistry()
	registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	return nil
}

// runRoot is the principal function for the binary.
func runRoot(_ *cobra.Command, _ []string) error {
	if printVersion {
		fmt.Println(version.Version)
		return nil
	}

	_, s, err := net.ParseCIDR(subnet)
	if err != nil {
		return fmt.Errorf("failed to parse %q as CIDR: %v", subnet, err)
	}

	if hostname == "" {
		var err error
		hostname, err = os.Hostname()
		if hostname == "" || err != nil {
			return errors.New("failed to determine hostname")
		}
	}

	e := encapsulation.Strategy(encapsulate)
	switch e {
	case encapsulation.Never:
	case encapsulation.CrossSubnet:
	case encapsulation.Always:
	default:
		return fmt.Errorf("encapsulation %v unknown; possible values are: %s", encapsulate, availableEncapsulations)
	}

	var enc encapsulation.Encapsulator
	switch compatibility {
	case "flannel":
		enc = encapsulation.NewFlannel(e)
	case "cilium":
		enc = encapsulation.NewCilium(e)
	default:
		enc = encapsulation.NewIPIP(e, dropOtherIpIpTraffic)
	}

	gr := mesh.Granularity(granularity)
	switch gr {
	case mesh.LogicalGranularity:
	case mesh.FullGranularity:
	default:
		return fmt.Errorf("mesh granularity %v unknown; possible values are: %s", granularity, availableGranularities)
	}

	var b mesh.Backend
	switch backend {
	case k8s.Backend:
		config, err := clientcmd.BuildConfigFromFlags(master, kubeconfig)
		if err != nil {
			return fmt.Errorf("failed to create Kubernetes config: %v", err)
		}
		c := kubernetes.NewForConfigOrDie(config)
		kc := kiloclient.NewForConfigOrDie(config)
		ec := apiextensions.NewForConfigOrDie(config)
		b = k8s.New(c, kc, ec, topologyLabel, log.With(logger, "component", "k8s backend"))
	default:
		return fmt.Errorf("backend %v unknown; possible values are: %s", backend, availableBackends)
	}

	if port < 1 || port > 1<<16-1 {
		return fmt.Errorf("invalid port: port mus be in range [%d:%d], but got %d", 1, 1<<16-1, port)
	}
	m, err := mesh.New(b, enc, gr, hostname, port, s, local, cni, cniPath, iface, cleanUpIface, createIface, mtu, resyncPeriod, prioritisePrivateAddr, iptablesForwardRule, log.With(logger, "component", "kilo"))
	if err != nil {
		return fmt.Errorf("failed to create Kilo mesh: %v", err)
	}

	m.RegisterMetrics(registry)

	var g run.Group
	{
		h := internalserver.NewHandler(
			internalserver.WithName("Internal Kilo API"),
			internalserver.WithPrometheusRegistry(registry),
			internalserver.WithPProf(),
		)
		h.AddEndpoint("/health", "Exposes health checks", healthHandler)
		h.AddEndpoint("/graph", "Exposes Kilo mesh topology graph", (&graphHandler{m, gr, &hostname, s}).ServeHTTP)
		// Run the HTTP server.
		l, err := net.Listen("tcp", listen)
		if err != nil {
			return fmt.Errorf("failed to listen on %s: %v", listen, err)
		}

		g.Add(func() error {
			if err := http.Serve(l, h); err != nil && err != http.ErrServerClosed {
				return fmt.Errorf("error: server exited unexpectedly: %v", err)
			}
			return nil
		}, func(error) {
			l.Close()
		})
	}

	{
		ctx, cancel := context.WithCancel(context.Background())
		// Start the mesh.
		g.Add(func() error {
			logger.Log("msg", fmt.Sprintf("Starting Kilo network mesh '%v'.", version.Version))
			if err := m.Run(ctx); err != nil {
				return fmt.Errorf("error: Kilo exited unexpectedly: %v", err)
			}
			return nil
		}, func(error) {
			cancel()
		})
	}

	{
		// Exit gracefully on SIGINT and SIGTERM.
		term := make(chan os.Signal, 1)
		signal.Notify(term, syscall.SIGINT, syscall.SIGTERM)
		cancel := make(chan struct{})
		g.Add(func() error {
			for {
				select {
				case <-term:
					logger.Log("msg", "caught interrupt; gracefully cleaning up; see you next time!")
					return nil
				case <-cancel:
					return nil
				}
			}
		}, func(error) {
			close(cancel)
		})
	}

	return g.Run()
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version and exit.",
	Run:   func(_ *cobra.Command, _ []string) { fmt.Println(version.Version) },
}

func main() {
	cmd.AddCommand(webhookCmd, versionCmd)
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
