// Copyright 2019 the Kilo authors
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
	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	flag "github.com/spf13/pflag"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/squat/kilo/pkg/encapsulation"
	"github.com/squat/kilo/pkg/k8s"
	kiloclient "github.com/squat/kilo/pkg/k8s/clientset/versioned"
	"github.com/squat/kilo/pkg/mesh"
	"github.com/squat/kilo/pkg/version"
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

// Main is the principal function for the binary, wrapped only by `main` for convenience.
func Main() error {
	backend := flag.String("backend", k8s.Backend, fmt.Sprintf("The backend for the mesh. Possible values: %s", availableBackends))
	cleanUpIface := flag.Bool("clean-up-interface", false, "Should Kilo delete its interface when it shuts down?")
	createIface := flag.Bool("create-interface", true, "Should kilo create an interface on startup?")
	cni := flag.Bool("cni", true, "Should Kilo manage the node's CNI configuration?")
	cniPath := flag.String("cni-path", mesh.DefaultCNIPath, "Path to CNI config.")
	compatibility := flag.String("compatibility", "", fmt.Sprintf("Should Kilo run in compatibility mode? Possible values: %s", availableCompatibilities))
	encapsulate := flag.String("encapsulate", string(encapsulation.Always), fmt.Sprintf("When should Kilo encapsulate packets within a location? Possible values: %s", availableEncapsulations))
	granularity := flag.String("mesh-granularity", string(mesh.LogicalGranularity), fmt.Sprintf("The granularity of the network mesh to create. Possible values: %s", availableGranularities))
	kubeconfig := flag.String("kubeconfig", "", "Path to kubeconfig.")
	hostname := flag.String("hostname", "", "Hostname of the node on which this process is running.")
	iface := flag.String("interface", mesh.DefaultKiloInterface, "Name of the Kilo interface to use; if it does not exist, it will be created.")
	listen := flag.String("listen", ":1107", "The address at which to listen for health and metrics.")
	local := flag.Bool("local", true, "Should Kilo manage routes within a location?")
	logLevel := flag.String("log-level", logLevelInfo, fmt.Sprintf("Log level to use. Possible values: %s", availableLogLevels))
	master := flag.String("master", "", "The address of the Kubernetes API server (overrides any value in kubeconfig).")
	topologyLabel := flag.String("topology-label", k8s.RegionLabelKey, "Kubernetes node label used to group nodes into logical locations.")
	var port uint
	flag.UintVar(&port, "port", mesh.DefaultKiloPort, "The port over which WireGuard peers should communicate.")
	subnet := flag.String("subnet", mesh.DefaultKiloSubnet.String(), "CIDR from which to allocate addresses for WireGuard interfaces.")
	resyncPeriod := flag.Duration("resync-period", 30*time.Second, "How often should the Kilo controllers reconcile?")
	printVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *printVersion {
		fmt.Println(version.Version)
		return nil
	}

	_, s, err := net.ParseCIDR(*subnet)
	if err != nil {
		return fmt.Errorf("failed to parse %q as CIDR: %v", *subnet, err)
	}

	if *hostname == "" {
		var err error
		*hostname, err = os.Hostname()
		if *hostname == "" || err != nil {
			return errors.New("failed to determine hostname")
		}
	}

	logger := log.NewJSONLogger(log.NewSyncWriter(os.Stdout))
	switch *logLevel {
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
		return fmt.Errorf("log level %v unknown; possible values are: %s", *logLevel, availableLogLevels)
	}
	logger = log.With(logger, "ts", log.DefaultTimestampUTC)
	logger = log.With(logger, "caller", log.DefaultCaller)

	e := encapsulation.Strategy(*encapsulate)
	switch e {
	case encapsulation.Never:
	case encapsulation.CrossSubnet:
	case encapsulation.Always:
	default:
		return fmt.Errorf("encapsulation %v unknown; possible values are: %s", *encapsulate, availableEncapsulations)
	}

	var enc encapsulation.Encapsulator
	switch *compatibility {
	case "flannel":
		enc = encapsulation.NewFlannel(e)
	default:
		enc = encapsulation.NewIPIP(e)
	}

	gr := mesh.Granularity(*granularity)
	switch gr {
	case mesh.LogicalGranularity:
	case mesh.FullGranularity:
	default:
		return fmt.Errorf("mesh granularity %v unknown; possible values are: %s", *granularity, availableGranularities)
	}

	var b mesh.Backend
	switch *backend {
	case k8s.Backend:
		config, err := clientcmd.BuildConfigFromFlags(*master, *kubeconfig)
		if err != nil {
			return fmt.Errorf("failed to create Kubernetes config: %v", err)
		}
		c := kubernetes.NewForConfigOrDie(config)
		kc := kiloclient.NewForConfigOrDie(config)
		ec := apiextensions.NewForConfigOrDie(config)
		b = k8s.New(c, kc, ec, *topologyLabel)
	default:
		return fmt.Errorf("backend %v unknown; possible values are: %s", *backend, availableBackends)
	}

	m, err := mesh.New(b, enc, gr, *hostname, uint32(port), s, *local, *cni, *cniPath, *iface, *cleanUpIface, *createIface, *resyncPeriod, log.With(logger, "component", "kilo"))
	if err != nil {
		return fmt.Errorf("failed to create Kilo mesh: %v", err)
	}

	r := prometheus.NewRegistry()
	r.MustRegister(
		prometheus.NewGoCollector(),
		prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}),
	)
	m.RegisterMetrics(r)

	var g run.Group
	{
		// Run the HTTP server.
		mux := http.NewServeMux()
		mux.Handle("/health", &healthHandler{})
		mux.Handle("/graph", &graphHandler{m, gr, hostname, s})
		mux.Handle("/metrics", promhttp.HandlerFor(r, promhttp.HandlerOpts{}))
		l, err := net.Listen("tcp", *listen)
		if err != nil {
			return fmt.Errorf("failed to listen on %s: %v", *listen, err)
		}

		g.Add(func() error {
			if err := http.Serve(l, mux); err != nil && err != http.ErrServerClosed {
				return fmt.Errorf("error: server exited unexpectedly: %v", err)
			}
			return nil
		}, func(error) {
			l.Close()
		})
	}

	{
		// Start the mesh.
		g.Add(func() error {
			logger.Log("msg", fmt.Sprintf("Starting Kilo network mesh '%v'.", version.Version))
			if err := m.Run(); err != nil {
				return fmt.Errorf("error: Kilo exited unexpectedly: %v", err)
			}
			return nil
		}, func(error) {
			m.Stop()
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

func main() {
	if err := Main(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
