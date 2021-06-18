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
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

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
	availableGranularities = strings.Join([]string{
		string(mesh.LogicalGranularity),
		string(mesh.FullGranularity),
		string(mesh.AutoGranularity),
	}, ", ")
	availableLogLevels = strings.Join([]string{
		logLevelAll,
		logLevelDebug,
		logLevelInfo,
		logLevelWarn,
		logLevelError,
		logLevelNone,
	}, ", ")
	opts struct {
		backend     mesh.Backend
		granularity mesh.Granularity
		port        uint32
	}
	backend       string
	granularity   string
	kubeconfig    string
	topologyLabel string
)

func runRoot(_ *cobra.Command, _ []string) error {
	opts.granularity = mesh.Granularity(granularity)
	switch opts.granularity {
	case mesh.LogicalGranularity:
	case mesh.FullGranularity:
	case mesh.AutoGranularity:
	default:
		return fmt.Errorf("mesh granularity %v unknown; posible values are: %s", granularity, availableGranularities)
	}

	switch backend {
	case k8s.Backend:
		config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return fmt.Errorf("failed to create Kubernetes config: %v", err)
		}
		c := kubernetes.NewForConfigOrDie(config)
		kc := kiloclient.NewForConfigOrDie(config)
		ec := apiextensions.NewForConfigOrDie(config)
		opts.backend = k8s.New(c, kc, ec, topologyLabel)
	default:
		return fmt.Errorf("backend %v unknown; posible values are: %s", backend, availableBackends)
	}

	if err := opts.backend.Nodes().Init(make(chan struct{})); err != nil {
		return fmt.Errorf("failed to initialize node backend: %v", err)
	}

	if err := opts.backend.Peers().Init(make(chan struct{})); err != nil {
		return fmt.Errorf("failed to initialize peer backend: %v", err)
	}
	return nil
}

func main() {
	cmd := &cobra.Command{
		Use:               "kgctl",
		Short:             "Manage a Kilo network",
		Long:              "",
		PersistentPreRunE: runRoot,
		Version:           version.Version,
	}
	cmd.PersistentFlags().StringVar(&backend, "backend", k8s.Backend, fmt.Sprintf("The backend for the mesh. Possible values: %s", availableBackends))
	cmd.PersistentFlags().StringVar(&granularity, "mesh-granularity", string(mesh.AutoGranularity), fmt.Sprintf("The granularity of the network mesh to create. Possible values: %s", availableGranularities))
	defaultKubeconfig := os.Getenv("KUBECONFIG")
	if _, err := os.Stat(defaultKubeconfig); os.IsNotExist(err) {
		defaultKubeconfig = filepath.Join(os.Getenv("HOME"), ".kube/config")
	}
	cmd.PersistentFlags().StringVar(&kubeconfig, "kubeconfig", defaultKubeconfig, "Path to kubeconfig.")
	cmd.PersistentFlags().Uint32Var(&opts.port, "port", mesh.DefaultKiloPort, "The WireGuard port over which the nodes communicate.")
	cmd.PersistentFlags().StringVar(&topologyLabel, "topology-label", k8s.RegionLabelKey, "Kubernetes node label used to group nodes into logical locations.")

	for _, subCmd := range []*cobra.Command{
		graph(),
		showConf(),
	} {
		cmd.AddCommand(subCmd)
	}

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func optainGranularity(gr mesh.Granularity, ns []*mesh.Node) (mesh.Granularity, error) {
	if gr == mesh.AutoGranularity {
		if len(ns) == 0 {
			return gr, errors.New("could not get any nodes")
		}
		ret := mesh.Granularity(ns[0].Granularity)
		switch ret {
		case mesh.LogicalGranularity:
		case mesh.FullGranularity:
		default:
			return ret, fmt.Errorf("mesh granularity %v is not supported", opts.granularity)
		}
		return ret, nil
	}
	return gr, nil
}
