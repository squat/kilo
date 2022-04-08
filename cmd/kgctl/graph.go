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
	"fmt"

	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/squat/kilo/pkg/mesh"
)

func graph() *cobra.Command {
	return &cobra.Command{
		Use:   "graph",
		Short: "Generates a graph of the Kilo network",
		RunE:  runGraph,
	}
}

func runGraph(_ *cobra.Command, _ []string) error {
	ns, err := opts.backend.Nodes().List()
	if err != nil {
		return fmt.Errorf("failed to list nodes: %w", err)
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
		return fmt.Errorf("did not find any valid Kilo nodes in the cluster")
	}
	peers := make(map[string]*mesh.Peer)
	for _, p := range ps {
		if p.Ready() {
			peers[p.Name] = p
		}
	}
	t, err := mesh.NewTopology(nodes, peers, opts.granularity, hostname, 0, wgtypes.Key{}, subnet, nodes[hostname].PersistentKeepalive, nil)
	if err != nil {
		return fmt.Errorf("failed to create topology: %w", err)
	}
	g, err := t.Dot()
	if err != nil {
		return fmt.Errorf("failed to generate graph: %w", err)
	}
	fmt.Println(g)
	return nil
}
