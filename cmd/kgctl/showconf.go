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
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
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
		allowedIPs []net.IPNet
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
	cmd.PersistentFlags().StringSliceVar(&allowedIPs, "allowed-ips", []string{}, "Add the given IPs to the allowed IPs of the configuration. Only valid when combined with 'as-peer'.")

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
		return fmt.Errorf("output format %s unknown; posible values are: %s", showConfOpts.output, availableOutputFormats)
	}
	for i := range allowedIPs {
		_, aip, err := net.ParseCIDR(allowedIPs[i])
		if err != nil {
			return fmt.Errorf("allowed-ips must contain only valid CIDRs; got %q", allowedIPs[i])
		}
		showConfOpts.allowedIPs = append(showConfOpts.allowedIPs, *aip)
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

	t, err := mesh.NewTopology(nodes, peers, opts.granularity, hostname, int(opts.port), wgtypes.Key{}, subnet, nil, nodes[hostname].PersistentKeepalive, nil)
	if err != nil {
		return fmt.Errorf("failed to create topology: %w", err)
	}

	var found bool
	for _, p := range t.PeerConf("").Peers {
		if p.PublicKey == nodes[hostname].Key {
			found = true
			break
		}
	}
	if !found {
		_, err := os.Stderr.WriteString(fmt.Sprintf("Node %q is not a leader node\n", hostname))
		return err
	}

	if !showConfOpts.asPeer {
		c, err := t.Conf().Bytes()
		if err != nil {
			return fmt.Errorf("failed to generate configuration: %w", err)
		}
		_, err = os.Stdout.Write(c)
		return err
	}

	switch showConfOpts.output {
	case outputFormatJSON:
		fallthrough
	case outputFormatYAML:
		p := t.AsPeer()
		if p == nil {
			return errors.New("cannot generate config from nil peer")
		}
		p.AllowedIPs = append(p.AllowedIPs, showConfOpts.allowedIPs...)
		p.DeduplicateIPs()
		k8sp := translatePeer(p)
		k8sp.Name = hostname
		return showConfOpts.serializer.Encode(k8sp, os.Stdout)
	case outputFormatWireGuard:
		p := t.AsPeer()
		if p == nil {
			return errors.New("cannot generate config from nil peer")
		}
		p.AllowedIPs = append(p.AllowedIPs, showConfOpts.allowedIPs...)
		p.DeduplicateIPs()
		c, err := (&wireguard.Conf{
			Peers: []wireguard.Peer{*p},
		}).Bytes()
		if err != nil {
			return fmt.Errorf("failed to generate configuration: %w", err)
		}
		_, err = os.Stdout.Write(c)
		return err
	}
	return nil
}

func runShowConfPeer(_ *cobra.Command, args []string) error {
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

	pka := time.Duration(0)
	if p := peers[peer].PersistentKeepaliveInterval; p != nil {
		pka = *p
	}
	t, err := mesh.NewTopology(nodes, peers, opts.granularity, hostname, mesh.DefaultKiloPort, wgtypes.Key{}, subnet, nil, pka, nil)
	if err != nil {
		return fmt.Errorf("failed to create topology: %w", err)
	}
	if !showConfOpts.asPeer {
		c, err := t.PeerConf(peer).Bytes()
		if err != nil {
			return fmt.Errorf("failed to generate configuration: %w", err)
		}
		_, err = os.Stdout.Write(c)
		return err
	}

	switch showConfOpts.output {
	case outputFormatJSON:
		fallthrough
	case outputFormatYAML:
		p := peers[peer]
		p.AllowedIPs = append(p.AllowedIPs, showConfOpts.allowedIPs...)
		p.DeduplicateIPs()
		k8sp := translatePeer(&p.Peer)
		k8sp.Name = peer
		return showConfOpts.serializer.Encode(k8sp, os.Stdout)
	case outputFormatWireGuard:
		p := &peers[peer].Peer
		p.AllowedIPs = append(p.AllowedIPs, showConfOpts.allowedIPs...)
		p.DeduplicateIPs()
		c, err := (&wireguard.Conf{
			Peers: []wireguard.Peer{*p},
		}).Bytes()
		if err != nil {
			return fmt.Errorf("failed to generate configuration: %w", err)
		}
		_, err = os.Stdout.Write(c)
		return err
	}
	return nil
}

// translatePeer translates a wireguard.Peer to a Peer CRD.
// TODO this function has many similarities to peerBackend.Set(name, peer)
func translatePeer(peer *wireguard.Peer) *v1alpha1.Peer {
	if peer == nil {
		return &v1alpha1.Peer{}
	}
	var aips []string
	for _, aip := range peer.AllowedIPs {
		// Skip any invalid IPs.
		// TODO all IPs should be valid, so no need to skip here?
		if aip.String() == (&net.IPNet{}).String() {
			continue
		}
		aips = append(aips, aip.String())
	}
	var endpoint *v1alpha1.PeerEndpoint
	if peer.Endpoint.Port() > 0 || !peer.Endpoint.HasDNS() {
		endpoint = &v1alpha1.PeerEndpoint{
			DNSOrIP: v1alpha1.DNSOrIP{
				IP:  peer.Endpoint.IP().String(),
				DNS: peer.Endpoint.DNS(),
			},
			Port: uint32(peer.Endpoint.Port()),
		}
	}
	var key string
	if peer.PublicKey != (wgtypes.Key{}) {
		key = peer.PublicKey.String()
	}
	var psk string
	if peer.PresharedKey != nil {
		psk = peer.PresharedKey.String()
	}
	var pka int
	if peer.PersistentKeepaliveInterval != nil && *peer.PersistentKeepaliveInterval > time.Duration(0) {
		pka = int(*peer.PersistentKeepaliveInterval)
	}
	return &v1alpha1.Peer{
		TypeMeta: metav1.TypeMeta{
			Kind:       v1alpha1.PeerKind,
			APIVersion: v1alpha1.SchemeGroupVersion.String(),
		},
		Spec: v1alpha1.PeerSpec{
			AllowedIPs:          aips,
			Endpoint:            endpoint,
			PersistentKeepalive: pka,
			PresharedKey:        psk,
			PublicKey:           key,
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
