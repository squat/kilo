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
	"os"
	"strings"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"

	"github.com/squat/kilo/pkg/k8s/apis/kilo/v1alpha1"
	"github.com/squat/kilo/pkg/mesh"
	"github.com/squat/kilo/pkg/wireguard"
)

const (
	outputFormatJSON      = "json"
	outputFormatWireGuard = "wireguard"
	outputFormatYAML      = "yaml"
)

var (
	availableOutputFormats = strings.Join([]string{
		outputFormatJSON,
		outputFormatWireGuard,
		outputFormatYAML,
	}, ", ")
	allowedIPs   []string
	showConfOpts struct {
		allowedIPs []*net.IPNet
		serializer *json.Serializer
		output     string
		asPeer     bool
	}
)

func showConf() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "showconf",
		Short:             "Show the WireGuard configuration for a node or peer in the Kilo network",
		PersistentPreRunE: runShowConf,
	}

	for _, subCmd := range []*cobra.Command{
		showConfNode(),
		showConfPeer(),
	} {
		cmd.AddCommand(subCmd)
	}
	cmd.PersistentFlags().BoolVar(&showConfOpts.asPeer, "as-peer", false, "Should the resource be shown as a peer? Useful to configure this resource as a peer of another WireGuard interface.")
	cmd.PersistentFlags().StringVarP(&showConfOpts.output, "output", "o", "wireguard", fmt.Sprintf("The output format of the resource. Only valid when combined with 'as-peer'. Possible values: %s", availableOutputFormats))
	cmd.PersistentFlags().StringSliceVar(&allowedIPs, "allowed-ips", []string{}, "Override the allowed IPs of the configuration. Only valid when combined with 'as-peer'.")

	return cmd
}

func runShowConf(c *cobra.Command, args []string) error {
	switch showConfOpts.output {
	case outputFormatJSON:
		showConfOpts.serializer = json.NewSerializer(json.DefaultMetaFactory, peerCreatorTyper{}, peerCreatorTyper{}, true)
	case outputFormatWireGuard:
	case outputFormatYAML:
		showConfOpts.serializer = json.NewYAMLSerializer(json.DefaultMetaFactory, peerCreatorTyper{}, peerCreatorTyper{})
	default:
		return fmt.Errorf("output format %v unknown; posible values are: %s", showConfOpts.output, availableOutputFormats)
	}
	for i := range allowedIPs {
		_, aip, err := net.ParseCIDR(allowedIPs[i])
		if err != nil {
			return fmt.Errorf("allowed-ips must contain only valid CIDRs; got %q", allowedIPs[i])
		}
		showConfOpts.allowedIPs = append(showConfOpts.allowedIPs, aip)
	}
	return runRoot(c, args)
}

func showConfNode() *cobra.Command {
	return &cobra.Command{
		Use:   "node [name]",
		Short: "Show the WireGuard configuration for a node in the Kilo network",
		RunE:  runShowConfNode,
		Args:  cobra.ExactArgs(1),
	}
}

func showConfPeer() *cobra.Command {
	return &cobra.Command{
		Use:   "peer [name]",
		Short: "Show the WireGuard configuration for a peer in the Kilo network",
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
	subnet := mesh.DefaultKiloSubnet
	nodes := make(map[string]*mesh.Node)
	for _, n := range ns {
		if n.Ready() {
			nodes[n.Name] = n
		}
		if n.WireGuardIP != nil {
			subnet = n.WireGuardIP
		}
	}
	subnet.IP = subnet.IP.Mask(subnet.Mask)
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

	t, err := mesh.NewTopology(nodes, peers, opts.granularity, hostname, mesh.DefaultKiloPort, []byte{}, subnet)
	if err != nil {
		return fmt.Errorf("failed to create topology: %v", err)
	}

	if !showConfOpts.asPeer {
		c, err := t.Conf().Bytes()
		if err != nil {
			return fmt.Errorf("failed to generate configuration: %v", err)
		}
		_, err = os.Stdout.Write(c)
		return err
	}

	switch showConfOpts.output {
	case outputFormatJSON:
		fallthrough
	case outputFormatYAML:
		p := translatePeer(t.AsPeer())
		p.Name = hostname
		if len(showConfOpts.allowedIPs) != 0 {
			p.Spec.AllowedIPs = allowedIPs
		}
		return showConfOpts.serializer.Encode(p, os.Stdout)
	case outputFormatWireGuard:
		p := t.AsPeer()
		if len(showConfOpts.allowedIPs) != 0 {
			p.AllowedIPs = showConfOpts.allowedIPs
		}
		c, err := (&wireguard.Conf{
			Peers: []*wireguard.Peer{p},
		}).Bytes()
		if err != nil {
			return fmt.Errorf("failed to generate configuration: %v", err)
		}
		_, err = os.Stdout.Write(c)
		return err
	}
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

	t, err := mesh.NewTopology(nodes, peers, opts.granularity, hostname, mesh.DefaultKiloPort, []byte{}, subnet)
	if err != nil {
		return fmt.Errorf("failed to create topology: %v", err)
	}
	if !showConfOpts.asPeer {
		c, err := t.PeerConf(peer).Bytes()
		if err != nil {
			return fmt.Errorf("failed to generate configuration: %v", err)
		}
		_, err = os.Stdout.Write(c)
		return err
	}

	switch showConfOpts.output {
	case outputFormatJSON:
		fallthrough
	case outputFormatYAML:
		p := translatePeer(&peers[peer].Peer)
		p.Name = peer
		if len(showConfOpts.allowedIPs) != 0 {
			p.Spec.AllowedIPs = allowedIPs
		}
		return showConfOpts.serializer.Encode(p, os.Stdout)
	case outputFormatWireGuard:
		p := &peers[peer].Peer
		if len(showConfOpts.allowedIPs) != 0 {
			p.AllowedIPs = showConfOpts.allowedIPs
		}
		c, err := (&wireguard.Conf{
			Peers: []*wireguard.Peer{p},
		}).Bytes()
		if err != nil {
			return fmt.Errorf("failed to generate configuration: %v", err)
		}
		_, err = os.Stdout.Write(c)
		return err
	}
	return nil
}

// translatePeer translates a wireguard.Peer to a Peer CRD.
func translatePeer(peer *wireguard.Peer) *v1alpha1.Peer {
	if peer == nil {
		return &v1alpha1.Peer{}
	}
	var aips []string
	for _, aip := range peer.AllowedIPs {
		// Skip any invalid IPs.
		if aip == nil {
			continue
		}
		aips = append(aips, aip.String())
	}
	var endpoint *v1alpha1.PeerEndpoint
	if peer.Endpoint != nil && peer.Endpoint.Port > 0 && peer.Endpoint.IP != nil {
		endpoint = &v1alpha1.PeerEndpoint{
			IP:   peer.Endpoint.IP.String(),
			Port: peer.Endpoint.Port,
		}
	}
	var key string
	if len(peer.PublicKey) > 0 {
		key = string(peer.PublicKey)
	}
	var pka int
	if peer.PersistentKeepalive > 0 {
		pka = peer.PersistentKeepalive
	}
	return &v1alpha1.Peer{
		TypeMeta: metav1.TypeMeta{
			Kind:       v1alpha1.PeerKind,
			APIVersion: v1alpha1.SchemeGroupVersion.String(),
		},
		Spec: v1alpha1.PeerSpec{
			AllowedIPs:          aips,
			Endpoint:            endpoint,
			PublicKey:           key,
			PersistentKeepalive: pka,
		},
	}
}

type peerCreatorTyper struct{}

func (p peerCreatorTyper) New(_ schema.GroupVersionKind) (runtime.Object, error) {
	return &v1alpha1.Peer{}, nil
}

func (p peerCreatorTyper) ObjectKinds(_ runtime.Object) ([]schema.GroupVersionKind, bool, error) {
	return []schema.GroupVersionKind{v1alpha1.PeerGVK}, false, nil
}

func (p peerCreatorTyper) Recognizes(_ schema.GroupVersionKind) bool {
	return true
}
