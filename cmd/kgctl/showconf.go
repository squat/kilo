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

	"github.com/spf13/cobra"
	"github.com/squat/kilo/pkg/mesh"
)

func showConf() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "showconf",
		Short: "Show the WireGuard configuration for a node or peer in the Kilo network",
		Long:  "",
	}

	for _, subCmd := range []*cobra.Command{
		showConfNode(),
		showConfPeer(),
	} {
		cmd.AddCommand(subCmd)
	}

	return cmd
}

func showConfNode() *cobra.Command {
	return &cobra.Command{
		Use:   "node",
		Short: "Show the WireGuard configuration for a node in the Kilo network",
		Long:  "",
		RunE:  runShowConfNode,
		Args:  cobra.ExactArgs(1),
	}
}

func showConfPeer() *cobra.Command {
	return &cobra.Command{
		Use:   "peer",
		Short: "Show the WireGuard configuration for a peer in the Kilo network",
		Long:  "",
		RunE:  runShowConfPeer,
		Args:  cobra.ExactArgs(1),
	}
}

func runShowConfNode(_ *cobra.Command, args []string) error {
	ns, err := opts.backend.Nodes().List()
	if err != nil {
		return fmt.Errorf("failed to list nodes: %v", err)
	}
	ps, err := opts.backend.Peers().List()
	if err != nil {
		return fmt.Errorf("failed to list peers: %v", err)
	}
	hostname := args[0]
	nodes := make(map[string]*mesh.Node)
	for _, n := range ns {
		if n.Ready() {
			nodes[n.Name] = n
		}
	}
	if len(nodes) == 0 {
		return errors.New("did not find any valid Kilo nodes in the cluster")
	}
	if _, ok := nodes[hostname]; !ok {
		return fmt.Errorf("did not find any node named %q in the cluster", hostname)
	}

	peers := make(map[string]*mesh.Peer)
	for _, p := range ps {
		if p.Ready() {
			peers[p.Name] = p
		}
	}

	t, err := mesh.NewTopology(nodes, peers, opts.granularity, hostname, mesh.DefaultKiloPort, []byte{}, opts.subnet)
	if err != nil {
		return fmt.Errorf("failed to create topology: %v", err)
	}
	c, err := t.Conf().Bytes()
	if err != nil {
		return fmt.Errorf("failed to generate configuration: %v", err)
	}
	fmt.Printf(string(c))
	return nil
}

func runShowConfPeer(_ *cobra.Command, args []string) error {
	ns, err := opts.backend.Nodes().List()
	if err != nil {
		return fmt.Errorf("failed to list nodes: %v", err)
	}
	ps, err := opts.backend.Peers().List()
	if err != nil {
		return fmt.Errorf("failed to list peers: %v", err)
	}
	var hostname string
	nodes := make(map[string]*mesh.Node)
	for _, n := range ns {
		if n.Ready() {
			nodes[n.Name] = n
			hostname = n.Name
		}
	}
	if len(nodes) == 0 {
		return errors.New("did not find any valid Kilo nodes in the cluster")
	}

	peer := args[0]
	peers := make(map[string]*mesh.Peer)
	for _, p := range ps {
		if p.Ready() {
			peers[p.Name] = p
		}
	}
	if _, ok := peers[peer]; !ok {
		return fmt.Errorf("did not find any peer named %q in the cluster", peer)
	}

	t, err := mesh.NewTopology(nodes, peers, opts.granularity, hostname, mesh.DefaultKiloPort, []byte{}, opts.subnet)
	if err != nil {
		return fmt.Errorf("failed to create topology: %v", err)
	}
	c, err := t.PeerConf(peer).Bytes()
	if err != nil {
		return fmt.Errorf("failed to generate configuration: %v", err)
	}
	fmt.Printf(string(c))
	return nil
}
