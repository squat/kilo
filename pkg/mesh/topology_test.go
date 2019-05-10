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

package mesh

import (
	"net"
	"strings"
	"testing"

	"github.com/kylelemons/godebug/pretty"
	"github.com/squat/kilo/pkg/wireguard"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func allowedIPs(ips ...string) string {
	return strings.Join(ips, ", ")
}

func setup(t *testing.T) (map[string]*Node, map[string]*Peer, []byte, uint32) {
	key := []byte("private")
	e1 := &net.IPNet{IP: net.ParseIP("10.1.0.1").To4(), Mask: net.CIDRMask(16, 32)}
	e2 := &net.IPNet{IP: net.ParseIP("10.1.0.2").To4(), Mask: net.CIDRMask(16, 32)}
	e3 := &net.IPNet{IP: net.ParseIP("10.1.0.3").To4(), Mask: net.CIDRMask(16, 32)}
	i1 := &net.IPNet{IP: net.ParseIP("192.168.0.1").To4(), Mask: net.CIDRMask(32, 32)}
	i2 := &net.IPNet{IP: net.ParseIP("192.168.0.2").To4(), Mask: net.CIDRMask(32, 32)}
	nodes := map[string]*Node{
		"a": {
			Name:       "a",
			ExternalIP: e1,
			InternalIP: i1,
			Location:   "1",
			Subnet:     &net.IPNet{IP: net.ParseIP("10.2.1.0"), Mask: net.CIDRMask(24, 32)},
			Key:        []byte("key1"),
		},
		"b": {
			Name:       "b",
			ExternalIP: e2,
			InternalIP: i1,
			Location:   "2",
			Subnet:     &net.IPNet{IP: net.ParseIP("10.2.2.0"), Mask: net.CIDRMask(24, 32)},
			Key:        []byte("key2"),
		},
		"c": {
			Name:       "c",
			ExternalIP: e3,
			InternalIP: i2,
			// Same location a node b.
			Location: "2",
			Subnet:   &net.IPNet{IP: net.ParseIP("10.2.3.0"), Mask: net.CIDRMask(24, 32)},
			Key:      []byte("key3"),
		},
	}
	peers := map[string]*Peer{
		"a": {
			Name: "a",
			Peer: wireguard.Peer{
				AllowedIPs: []*net.IPNet{
					{IP: net.ParseIP("10.5.0.1"), Mask: net.CIDRMask(24, 32)},
					{IP: net.ParseIP("10.5.0.2"), Mask: net.CIDRMask(24, 32)},
				},
				PublicKey: []byte("key4"),
			},
		},
		"b": {
			Name: "b",
			Peer: wireguard.Peer{
				AllowedIPs: []*net.IPNet{
					{IP: net.ParseIP("10.5.0.3"), Mask: net.CIDRMask(24, 32)},
				},
				Endpoint: &wireguard.Endpoint{
					IP:   net.ParseIP("192.168.0.1"),
					Port: DefaultKiloPort,
				},
				PublicKey: []byte("key5"),
			},
		},
	}
	return nodes, peers, key, DefaultKiloPort
}

func TestNewTopology(t *testing.T) {
	nodes, peers, key, port := setup(t)

	w1 := net.ParseIP("10.4.0.1").To4()
	w2 := net.ParseIP("10.4.0.2").To4()
	w3 := net.ParseIP("10.4.0.3").To4()
	for _, tc := range []struct {
		name        string
		granularity Granularity
		hostname    string
		result      *Topology
	}{
		{
			name:        "logical from a",
			granularity: LogicalGranularity,
			hostname:    nodes["a"].Name,
			result: &Topology{
				hostname:      nodes["a"].Name,
				leader:        true,
				location:      nodes["a"].Location,
				subnet:        DefaultKiloSubnet,
				privateIP:     nodes["a"].InternalIP,
				wireGuardCIDR: &net.IPNet{IP: w1, Mask: net.CIDRMask(16, 32)},
				segments: []*segment{
					{
						allowedIPs:  []*net.IPNet{nodes["a"].Subnet, nodes["a"].InternalIP, {IP: w1, Mask: net.CIDRMask(32, 32)}},
						endpoint:    nodes["a"].ExternalIP.IP,
						key:         nodes["a"].Key,
						location:    nodes["a"].Location,
						cidrs:       []*net.IPNet{nodes["a"].Subnet},
						hostnames:   []string{"a"},
						privateIPs:  []net.IP{nodes["a"].InternalIP.IP},
						wireGuardIP: w1,
					},
					{
						allowedIPs:  []*net.IPNet{nodes["b"].Subnet, nodes["b"].InternalIP, nodes["c"].Subnet, nodes["c"].InternalIP, {IP: w2, Mask: net.CIDRMask(32, 32)}},
						endpoint:    nodes["b"].ExternalIP.IP,
						key:         nodes["b"].Key,
						location:    nodes["b"].Location,
						cidrs:       []*net.IPNet{nodes["b"].Subnet, nodes["c"].Subnet},
						hostnames:   []string{"b", "c"},
						privateIPs:  []net.IP{nodes["b"].InternalIP.IP, nodes["c"].InternalIP.IP},
						wireGuardIP: w2,
					},
				},
				peers: []*Peer{peers["a"], peers["b"]},
			},
		},
		{
			name:        "logical from b",
			granularity: LogicalGranularity,
			hostname:    nodes["b"].Name,
			result: &Topology{
				hostname:      nodes["b"].Name,
				leader:        true,
				location:      nodes["b"].Location,
				subnet:        DefaultKiloSubnet,
				privateIP:     nodes["b"].InternalIP,
				wireGuardCIDR: &net.IPNet{IP: w2, Mask: net.CIDRMask(16, 32)},
				segments: []*segment{
					{
						allowedIPs:  []*net.IPNet{nodes["a"].Subnet, nodes["a"].InternalIP, {IP: w1, Mask: net.CIDRMask(32, 32)}},
						endpoint:    nodes["a"].ExternalIP.IP,
						key:         nodes["a"].Key,
						location:    nodes["a"].Location,
						cidrs:       []*net.IPNet{nodes["a"].Subnet},
						hostnames:   []string{"a"},
						privateIPs:  []net.IP{nodes["a"].InternalIP.IP},
						wireGuardIP: w1,
					},
					{
						allowedIPs:  []*net.IPNet{nodes["b"].Subnet, nodes["b"].InternalIP, nodes["c"].Subnet, nodes["c"].InternalIP, {IP: w2, Mask: net.CIDRMask(32, 32)}},
						endpoint:    nodes["b"].ExternalIP.IP,
						key:         nodes["b"].Key,
						location:    nodes["b"].Location,
						cidrs:       []*net.IPNet{nodes["b"].Subnet, nodes["c"].Subnet},
						hostnames:   []string{"b", "c"},
						privateIPs:  []net.IP{nodes["b"].InternalIP.IP, nodes["c"].InternalIP.IP},
						wireGuardIP: w2,
					},
				},
				peers: []*Peer{peers["a"], peers["b"]},
			},
		},
		{
			name:        "logical from c",
			granularity: LogicalGranularity,
			hostname:    nodes["c"].Name,
			result: &Topology{
				hostname:      nodes["c"].Name,
				leader:        false,
				location:      nodes["b"].Location,
				subnet:        DefaultKiloSubnet,
				privateIP:     nodes["c"].InternalIP,
				wireGuardCIDR: nil,
				segments: []*segment{
					{
						allowedIPs:  []*net.IPNet{nodes["a"].Subnet, nodes["a"].InternalIP, {IP: w1, Mask: net.CIDRMask(32, 32)}},
						endpoint:    nodes["a"].ExternalIP.IP,
						key:         nodes["a"].Key,
						location:    nodes["a"].Location,
						cidrs:       []*net.IPNet{nodes["a"].Subnet},
						hostnames:   []string{"a"},
						privateIPs:  []net.IP{nodes["a"].InternalIP.IP},
						wireGuardIP: w1,
					},
					{
						allowedIPs:  []*net.IPNet{nodes["b"].Subnet, nodes["b"].InternalIP, nodes["c"].Subnet, nodes["c"].InternalIP, {IP: w2, Mask: net.CIDRMask(32, 32)}},
						endpoint:    nodes["b"].ExternalIP.IP,
						key:         nodes["b"].Key,
						location:    nodes["b"].Location,
						cidrs:       []*net.IPNet{nodes["b"].Subnet, nodes["c"].Subnet},
						hostnames:   []string{"b", "c"},
						privateIPs:  []net.IP{nodes["b"].InternalIP.IP, nodes["c"].InternalIP.IP},
						wireGuardIP: w2,
					},
				},
				peers: []*Peer{peers["a"], peers["b"]},
			},
		},
		{
			name:        "full from a",
			granularity: FullGranularity,
			hostname:    nodes["a"].Name,
			result: &Topology{
				hostname:      nodes["a"].Name,
				leader:        true,
				location:      nodes["a"].Name,
				subnet:        DefaultKiloSubnet,
				privateIP:     nodes["a"].InternalIP,
				wireGuardCIDR: &net.IPNet{IP: w1, Mask: net.CIDRMask(16, 32)},
				segments: []*segment{
					{
						allowedIPs:  []*net.IPNet{nodes["a"].Subnet, nodes["a"].InternalIP, {IP: w1, Mask: net.CIDRMask(32, 32)}},
						endpoint:    nodes["a"].ExternalIP.IP,
						key:         nodes["a"].Key,
						location:    nodes["a"].Name,
						cidrs:       []*net.IPNet{nodes["a"].Subnet},
						hostnames:   []string{"a"},
						privateIPs:  []net.IP{nodes["a"].InternalIP.IP},
						wireGuardIP: w1,
					},
					{
						allowedIPs:  []*net.IPNet{nodes["b"].Subnet, nodes["b"].InternalIP, {IP: w2, Mask: net.CIDRMask(32, 32)}},
						endpoint:    nodes["b"].ExternalIP.IP,
						key:         nodes["b"].Key,
						location:    nodes["b"].Name,
						cidrs:       []*net.IPNet{nodes["b"].Subnet},
						hostnames:   []string{"b"},
						privateIPs:  []net.IP{nodes["b"].InternalIP.IP},
						wireGuardIP: w2,
					},
					{
						allowedIPs:  []*net.IPNet{nodes["c"].Subnet, nodes["c"].InternalIP, {IP: w3, Mask: net.CIDRMask(32, 32)}},
						endpoint:    nodes["c"].ExternalIP.IP,
						key:         nodes["c"].Key,
						location:    nodes["c"].Name,
						cidrs:       []*net.IPNet{nodes["c"].Subnet},
						hostnames:   []string{"c"},
						privateIPs:  []net.IP{nodes["c"].InternalIP.IP},
						wireGuardIP: w3,
					},
				},
				peers: []*Peer{peers["a"], peers["b"]},
			},
		},
		{
			name:        "full from b",
			granularity: FullGranularity,
			hostname:    nodes["b"].Name,
			result: &Topology{
				hostname:      nodes["b"].Name,
				leader:        true,
				location:      nodes["b"].Name,
				subnet:        DefaultKiloSubnet,
				privateIP:     nodes["b"].InternalIP,
				wireGuardCIDR: &net.IPNet{IP: w2, Mask: net.CIDRMask(16, 32)},
				segments: []*segment{
					{
						allowedIPs:  []*net.IPNet{nodes["a"].Subnet, nodes["a"].InternalIP, {IP: w1, Mask: net.CIDRMask(32, 32)}},
						endpoint:    nodes["a"].ExternalIP.IP,
						key:         nodes["a"].Key,
						location:    nodes["a"].Name,
						cidrs:       []*net.IPNet{nodes["a"].Subnet},
						hostnames:   []string{"a"},
						privateIPs:  []net.IP{nodes["a"].InternalIP.IP},
						wireGuardIP: w1,
					},
					{
						allowedIPs:  []*net.IPNet{nodes["b"].Subnet, nodes["b"].InternalIP, {IP: w2, Mask: net.CIDRMask(32, 32)}},
						endpoint:    nodes["b"].ExternalIP.IP,
						key:         nodes["b"].Key,
						location:    nodes["b"].Name,
						cidrs:       []*net.IPNet{nodes["b"].Subnet},
						hostnames:   []string{"b"},
						privateIPs:  []net.IP{nodes["b"].InternalIP.IP},
						wireGuardIP: w2,
					},
					{
						allowedIPs:  []*net.IPNet{nodes["c"].Subnet, nodes["c"].InternalIP, {IP: w3, Mask: net.CIDRMask(32, 32)}},
						endpoint:    nodes["c"].ExternalIP.IP,
						key:         nodes["c"].Key,
						location:    nodes["c"].Name,
						cidrs:       []*net.IPNet{nodes["c"].Subnet},
						hostnames:   []string{"c"},
						privateIPs:  []net.IP{nodes["c"].InternalIP.IP},
						wireGuardIP: w3,
					},
				},
				peers: []*Peer{peers["a"], peers["b"]},
			},
		},
		{
			name:        "full from c",
			granularity: FullGranularity,
			hostname:    nodes["c"].Name,
			result: &Topology{
				hostname:      nodes["c"].Name,
				leader:        true,
				location:      nodes["c"].Name,
				subnet:        DefaultKiloSubnet,
				privateIP:     nodes["c"].InternalIP,
				wireGuardCIDR: &net.IPNet{IP: w3, Mask: net.CIDRMask(16, 32)},
				segments: []*segment{
					{
						allowedIPs:  []*net.IPNet{nodes["a"].Subnet, nodes["a"].InternalIP, {IP: w1, Mask: net.CIDRMask(32, 32)}},
						endpoint:    nodes["a"].ExternalIP.IP,
						key:         nodes["a"].Key,
						location:    nodes["a"].Name,
						cidrs:       []*net.IPNet{nodes["a"].Subnet},
						hostnames:   []string{"a"},
						privateIPs:  []net.IP{nodes["a"].InternalIP.IP},
						wireGuardIP: w1,
					},
					{
						allowedIPs:  []*net.IPNet{nodes["b"].Subnet, nodes["b"].InternalIP, {IP: w2, Mask: net.CIDRMask(32, 32)}},
						endpoint:    nodes["b"].ExternalIP.IP,
						key:         nodes["b"].Key,
						location:    nodes["b"].Name,
						cidrs:       []*net.IPNet{nodes["b"].Subnet},
						hostnames:   []string{"b"},
						privateIPs:  []net.IP{nodes["b"].InternalIP.IP},
						wireGuardIP: w2,
					},
					{
						allowedIPs:  []*net.IPNet{nodes["c"].Subnet, nodes["c"].InternalIP, {IP: w3, Mask: net.CIDRMask(32, 32)}},
						endpoint:    nodes["c"].ExternalIP.IP,
						key:         nodes["c"].Key,
						location:    nodes["c"].Name,
						cidrs:       []*net.IPNet{nodes["c"].Subnet},
						hostnames:   []string{"c"},
						privateIPs:  []net.IP{nodes["c"].InternalIP.IP},
						wireGuardIP: w3,
					},
				},
				peers: []*Peer{peers["a"], peers["b"]},
			},
		},
	} {
		tc.result.key = key
		tc.result.port = port
		topo, err := NewTopology(nodes, peers, tc.granularity, tc.hostname, port, key, DefaultKiloSubnet)
		if err != nil {
			t.Errorf("test case %q: failed to generate Topology: %v", tc.name, err)
		}
		if diff := pretty.Compare(topo, tc.result); diff != "" {
			t.Errorf("test case %q: got diff: %v", tc.name, diff)
		}
	}
}

func mustTopo(t *testing.T, nodes map[string]*Node, peers map[string]*Peer, granularity Granularity, hostname string, port uint32, key []byte, subnet *net.IPNet) *Topology {
	topo, err := NewTopology(nodes, peers, granularity, hostname, port, key, subnet)
	if err != nil {
		t.Errorf("failed to generate Topology: %v", err)
	}
	return topo
}

func TestRoutes(t *testing.T) {
	nodes, peers, key, port := setup(t)
	kiloIface := 0
	privIface := 1
	pubIface := 2
	mustTopoForGranularityAndHost := func(granularity Granularity, hostname string) *Topology {
		return mustTopo(t, nodes, peers, granularity, hostname, port, key, DefaultKiloSubnet)
	}

	for _, tc := range []struct {
		name     string
		local    bool
		topology *Topology
		result   []*netlink.Route
	}{
		{
			name:     "logical from a",
			topology: mustTopoForGranularityAndHost(LogicalGranularity, nodes["a"].Name),
			result: []*netlink.Route{
				{
					Dst:       mustTopoForGranularityAndHost(LogicalGranularity, nodes["a"].Name).segments[1].cidrs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(LogicalGranularity, nodes["a"].Name).segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["b"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(LogicalGranularity, nodes["a"].Name).segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       mustTopoForGranularityAndHost(LogicalGranularity, nodes["a"].Name).segments[1].cidrs[1],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(LogicalGranularity, nodes["a"].Name).segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["c"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(LogicalGranularity, nodes["a"].Name).segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       peers["a"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       peers["a"].AllowedIPs[1],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       peers["b"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
			},
		},
		{
			name:     "logical from b",
			topology: mustTopoForGranularityAndHost(LogicalGranularity, nodes["b"].Name),
			result: []*netlink.Route{
				{
					Dst:       mustTopoForGranularityAndHost(LogicalGranularity, nodes["b"].Name).segments[0].cidrs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(LogicalGranularity, nodes["b"].Name).segments[0].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["a"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(LogicalGranularity, nodes["b"].Name).segments[0].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       peers["a"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       peers["a"].AllowedIPs[1],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       peers["b"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
			},
		},
		{
			name:     "logical from c",
			topology: mustTopoForGranularityAndHost(LogicalGranularity, nodes["c"].Name),
			result: []*netlink.Route{
				{
					Dst:       oneAddressCIDR(mustTopoForGranularityAndHost(LogicalGranularity, nodes["c"].Name).segments[0].wireGuardIP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["b"].InternalIP.IP,
					LinkIndex: privIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       mustTopoForGranularityAndHost(LogicalGranularity, nodes["c"].Name).segments[0].cidrs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["b"].InternalIP.IP,
					LinkIndex: privIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["a"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["b"].InternalIP.IP,
					LinkIndex: privIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(mustTopoForGranularityAndHost(LogicalGranularity, nodes["c"].Name).segments[1].wireGuardIP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["b"].InternalIP.IP,
					LinkIndex: privIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       peers["a"].AllowedIPs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["b"].InternalIP.IP,
					LinkIndex: privIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       peers["a"].AllowedIPs[1],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["b"].InternalIP.IP,
					LinkIndex: privIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       peers["b"].AllowedIPs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["b"].InternalIP.IP,
					LinkIndex: privIface,
					Protocol:  unix.RTPROT_STATIC,
				},
			},
		},
		{
			name:     "full from a",
			topology: mustTopoForGranularityAndHost(FullGranularity, nodes["a"].Name),
			result: []*netlink.Route{
				{
					Dst:       mustTopoForGranularityAndHost(FullGranularity, nodes["a"].Name).segments[1].cidrs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(FullGranularity, nodes["a"].Name).segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["b"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(FullGranularity, nodes["a"].Name).segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       mustTopoForGranularityAndHost(FullGranularity, nodes["a"].Name).segments[2].cidrs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(FullGranularity, nodes["a"].Name).segments[2].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["c"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(FullGranularity, nodes["a"].Name).segments[2].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       peers["a"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       peers["a"].AllowedIPs[1],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       peers["b"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
			},
		},
		{
			name:     "full from b",
			topology: mustTopoForGranularityAndHost(FullGranularity, nodes["b"].Name),
			result: []*netlink.Route{
				{
					Dst:       mustTopoForGranularityAndHost(FullGranularity, nodes["b"].Name).segments[0].cidrs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(FullGranularity, nodes["b"].Name).segments[0].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["a"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(FullGranularity, nodes["b"].Name).segments[0].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       mustTopoForGranularityAndHost(FullGranularity, nodes["b"].Name).segments[2].cidrs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(FullGranularity, nodes["b"].Name).segments[2].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["c"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(FullGranularity, nodes["b"].Name).segments[2].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       peers["a"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       peers["a"].AllowedIPs[1],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       peers["b"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
			},
		},
		{
			name:     "full from c",
			topology: mustTopoForGranularityAndHost(FullGranularity, nodes["c"].Name),
			result: []*netlink.Route{
				{
					Dst:       mustTopoForGranularityAndHost(FullGranularity, nodes["c"].Name).segments[0].cidrs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(FullGranularity, nodes["c"].Name).segments[0].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["a"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(FullGranularity, nodes["c"].Name).segments[0].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       mustTopoForGranularityAndHost(FullGranularity, nodes["c"].Name).segments[1].cidrs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(FullGranularity, nodes["c"].Name).segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["b"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(FullGranularity, nodes["c"].Name).segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       peers["a"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       peers["a"].AllowedIPs[1],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       peers["b"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
			},
		},
		{
			name:     "logical from a local",
			local:    true,
			topology: mustTopoForGranularityAndHost(LogicalGranularity, nodes["a"].Name),
			result: []*netlink.Route{
				{
					Dst:       nodes["b"].Subnet,
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(LogicalGranularity, nodes["a"].Name).segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["b"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(LogicalGranularity, nodes["a"].Name).segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       nodes["c"].Subnet,
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(LogicalGranularity, nodes["a"].Name).segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["c"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(LogicalGranularity, nodes["a"].Name).segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       peers["a"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       peers["a"].AllowedIPs[1],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       peers["b"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
			},
		},
		{
			name:     "logical from b local",
			local:    true,
			topology: mustTopoForGranularityAndHost(LogicalGranularity, nodes["b"].Name),
			result: []*netlink.Route{
				{
					Dst:       nodes["a"].Subnet,
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(LogicalGranularity, nodes["b"].Name).segments[0].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["a"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(LogicalGranularity, nodes["b"].Name).segments[0].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       nodes["c"].Subnet,
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["c"].InternalIP.IP,
					LinkIndex: privIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       peers["a"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       peers["a"].AllowedIPs[1],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       peers["b"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
			},
		},
		{
			name:     "logical from c local",
			local:    true,
			topology: mustTopoForGranularityAndHost(LogicalGranularity, nodes["c"].Name),
			result: []*netlink.Route{
				{
					Dst:       oneAddressCIDR(mustTopoForGranularityAndHost(LogicalGranularity, nodes["c"].Name).segments[0].wireGuardIP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["b"].InternalIP.IP,
					LinkIndex: privIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       nodes["a"].Subnet,
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["b"].InternalIP.IP,
					LinkIndex: privIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["a"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["b"].InternalIP.IP,
					LinkIndex: privIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(mustTopoForGranularityAndHost(LogicalGranularity, nodes["c"].Name).segments[1].wireGuardIP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["b"].InternalIP.IP,
					LinkIndex: privIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       nodes["b"].Subnet,
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["b"].InternalIP.IP,
					LinkIndex: privIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       peers["a"].AllowedIPs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["b"].InternalIP.IP,
					LinkIndex: privIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       peers["a"].AllowedIPs[1],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["b"].InternalIP.IP,
					LinkIndex: privIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       peers["b"].AllowedIPs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["b"].InternalIP.IP,
					LinkIndex: privIface,
					Protocol:  unix.RTPROT_STATIC,
				},
			},
		},
		{
			name:     "full from a local",
			local:    true,
			topology: mustTopoForGranularityAndHost(FullGranularity, nodes["a"].Name),
			result: []*netlink.Route{
				{
					Dst:       nodes["b"].Subnet,
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(FullGranularity, nodes["a"].Name).segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["b"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(FullGranularity, nodes["a"].Name).segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       nodes["c"].Subnet,
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(FullGranularity, nodes["a"].Name).segments[2].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["c"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(FullGranularity, nodes["a"].Name).segments[2].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       peers["a"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       peers["a"].AllowedIPs[1],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       peers["b"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
			},
		},
		{
			name:     "full from b local",
			local:    true,
			topology: mustTopoForGranularityAndHost(FullGranularity, nodes["b"].Name),
			result: []*netlink.Route{
				{
					Dst:       nodes["a"].Subnet,
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(FullGranularity, nodes["b"].Name).segments[0].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["a"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(FullGranularity, nodes["b"].Name).segments[0].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       nodes["c"].Subnet,
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(FullGranularity, nodes["b"].Name).segments[2].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["c"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(FullGranularity, nodes["b"].Name).segments[2].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       peers["a"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       peers["a"].AllowedIPs[1],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       peers["b"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
			},
		},
		{
			name:     "full from c local",
			local:    true,
			topology: mustTopoForGranularityAndHost(FullGranularity, nodes["c"].Name),
			result: []*netlink.Route{
				{
					Dst:       nodes["a"].Subnet,
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(FullGranularity, nodes["c"].Name).segments[0].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["a"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(FullGranularity, nodes["c"].Name).segments[0].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       nodes["b"].Subnet,
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(FullGranularity, nodes["c"].Name).segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["b"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(FullGranularity, nodes["c"].Name).segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       peers["a"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       peers["a"].AllowedIPs[1],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       peers["b"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
			},
		},
	} {
		routes := tc.topology.Routes(kiloIface, privIface, pubIface, tc.local, NeverEncapsulate)
		if diff := pretty.Compare(routes, tc.result); diff != "" {
			t.Errorf("test case %q: got diff: %v", tc.name, diff)
		}
	}
}

func TestConf(t *testing.T) {
	nodes, peers, key, port := setup(t)
	for _, tc := range []struct {
		name     string
		topology *Topology
		result   string
	}{
		{
			name:     "logical from a",
			topology: mustTopo(t, nodes, peers, LogicalGranularity, nodes["a"].Name, port, key, DefaultKiloSubnet),
			result: `[Interface]
PrivateKey = private
ListenPort = 51820

[Peer]
PublicKey = key2
Endpoint = 10.1.0.2:51820
AllowedIPs = 10.2.2.0/24, 192.168.0.1/32, 10.2.3.0/24, 192.168.0.2/32, 10.4.0.2/32

[Peer]
PublicKey = key4
PersistentKeepalive = 0
AllowedIPs = 10.5.0.1/24, 10.5.0.2/24

[Peer]
PublicKey = key5
Endpoint = 192.168.0.1:51820
PersistentKeepalive = 0
AllowedIPs = 10.5.0.3/24
`,
		},
		{
			name:     "logical from b",
			topology: mustTopo(t, nodes, peers, LogicalGranularity, nodes["b"].Name, port, key, DefaultKiloSubnet),
			result: `[Interface]
		PrivateKey = private
		ListenPort = 51820

		[Peer]
		PublicKey = key1
		Endpoint = 10.1.0.1:51820
		AllowedIPs = 10.2.1.0/24, 192.168.0.1/32, 10.4.0.1/32

		[Peer]
		PublicKey = key4
		PersistentKeepalive = 0
		AllowedIPs = 10.5.0.1/24, 10.5.0.2/24

		[Peer]
		PublicKey = key5
		Endpoint = 192.168.0.1:51820
		PersistentKeepalive = 0
		AllowedIPs = 10.5.0.3/24
		`,
		},
		{
			name:     "logical from c",
			topology: mustTopo(t, nodes, peers, LogicalGranularity, nodes["c"].Name, port, key, DefaultKiloSubnet),
			result: `[Interface]
		PrivateKey = private
		ListenPort = 51820

		[Peer]
		PublicKey = key1
		Endpoint = 10.1.0.1:51820
		AllowedIPs = 10.2.1.0/24, 192.168.0.1/32, 10.4.0.1/32

		[Peer]
		PublicKey = key4
		PersistentKeepalive = 0
		AllowedIPs = 10.5.0.1/24, 10.5.0.2/24

		[Peer]
		PublicKey = key5
		Endpoint = 192.168.0.1:51820
		PersistentKeepalive = 0
		AllowedIPs = 10.5.0.3/24
		`,
		},
		{
			name:     "full from a",
			topology: mustTopo(t, nodes, peers, FullGranularity, nodes["a"].Name, port, key, DefaultKiloSubnet),
			result: `[Interface]
		PrivateKey = private
		ListenPort = 51820

		[Peer]
		PublicKey = key2
		Endpoint = 10.1.0.2:51820
		AllowedIPs = 10.2.2.0/24, 192.168.0.1/32, 10.4.0.2/32

		[Peer]
		PublicKey = key3
		Endpoint = 10.1.0.3:51820
		AllowedIPs = 10.2.3.0/24, 192.168.0.2/32, 10.4.0.3/32

		[Peer]
		PublicKey = key4
		PersistentKeepalive = 0
		AllowedIPs = 10.5.0.1/24, 10.5.0.2/24

		[Peer]
		PublicKey = key5
		Endpoint = 192.168.0.1:51820
		PersistentKeepalive = 0
		AllowedIPs = 10.5.0.3/24
		`,
		},
		{
			name:     "full from b",
			topology: mustTopo(t, nodes, peers, FullGranularity, nodes["b"].Name, port, key, DefaultKiloSubnet),
			result: `[Interface]
		PrivateKey = private
		ListenPort = 51820

		[Peer]
		PublicKey = key1
		Endpoint = 10.1.0.1:51820
		AllowedIPs = 10.2.1.0/24, 192.168.0.1/32, 10.4.0.1/32

		[Peer]
		PublicKey = key3
		Endpoint = 10.1.0.3:51820
		AllowedIPs = 10.2.3.0/24, 192.168.0.2/32, 10.4.0.3/32

		[Peer]
		PublicKey = key4
		PersistentKeepalive = 0
		AllowedIPs = 10.5.0.1/24, 10.5.0.2/24

		[Peer]
		PublicKey = key5
		Endpoint = 192.168.0.1:51820
		PersistentKeepalive = 0
		AllowedIPs = 10.5.0.3/24
		`,
		},
		{
			name:     "full from c",
			topology: mustTopo(t, nodes, peers, FullGranularity, nodes["c"].Name, port, key, DefaultKiloSubnet),
			result: `[Interface]
		PrivateKey = private
		ListenPort = 51820

		[Peer]
		PublicKey = key1
		Endpoint = 10.1.0.1:51820
		AllowedIPs = 10.2.1.0/24, 192.168.0.1/32, 10.4.0.1/32

		[Peer]
		PublicKey = key2
		Endpoint = 10.1.0.2:51820
		AllowedIPs = 10.2.2.0/24, 192.168.0.1/32, 10.4.0.2/32

		[Peer]
		PublicKey = key4
		PersistentKeepalive = 0
		AllowedIPs = 10.5.0.1/24, 10.5.0.2/24

		[Peer]
		PublicKey = key5
		Endpoint = 192.168.0.1:51820
		PersistentKeepalive = 0
		AllowedIPs = 10.5.0.3/24
		`,
		},
	} {
		conf := tc.topology.Conf()
		if !conf.Equal(wireguard.Parse([]byte(tc.result))) {
			buf, err := conf.Bytes()
			if err != nil {
				t.Errorf("test case %q: failed to render conf: %v", tc.name, err)
			}
			t.Errorf("test case %q: expected %s got %s", tc.name, tc.result, string(buf))
		}
	}
}

func TestFindLeader(t *testing.T) {
	ip, e1, err := net.ParseCIDR("10.0.0.1/32")
	if err != nil {
		t.Fatalf("failed to parse external IP CIDR: %v", err)
	}
	e1.IP = ip
	ip, e2, err := net.ParseCIDR("8.8.8.8/32")
	if err != nil {
		t.Fatalf("failed to parse external IP CIDR: %v", err)
	}
	e2.IP = ip

	nodes := []*Node{
		{
			Name:       "a",
			ExternalIP: e1,
		},
		{
			Name:       "b",
			ExternalIP: e2,
		},
		{
			Name:       "c",
			ExternalIP: e2,
		},
		{
			Name:       "d",
			ExternalIP: e1,
			Leader:     true,
		},
		{
			Name:       "2",
			ExternalIP: e2,
			Leader:     true,
		},
	}
	for _, tc := range []struct {
		name  string
		nodes []*Node
		out   int
	}{
		{
			name:  "nil",
			nodes: nil,
			out:   0,
		},
		{
			name:  "one",
			nodes: []*Node{nodes[0]},
			out:   0,
		},
		{
			name:  "non-leaders",
			nodes: []*Node{nodes[0], nodes[1], nodes[2]},
			out:   1,
		},
		{
			name:  "leaders",
			nodes: []*Node{nodes[3], nodes[4]},
			out:   1,
		},
		{
			name:  "public",
			nodes: []*Node{nodes[1], nodes[2], nodes[4]},
			out:   2,
		},
		{
			name:  "private",
			nodes: []*Node{nodes[0], nodes[3]},
			out:   1,
		},
		{
			name:  "all",
			nodes: nodes,
			out:   4,
		},
	} {
		l := findLeader(tc.nodes)
		if l != tc.out {
			t.Errorf("test case %q: expected %d got %d", tc.name, tc.out, l)
		}
	}
}

func TestDeduplicatePeerIPs(t *testing.T) {
	p1 := &Peer{
		Name: "1",
		Peer: wireguard.Peer{
			PublicKey: []byte("key1"),
			AllowedIPs: []*net.IPNet{
				{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)},
				{IP: net.ParseIP("10.0.0.2"), Mask: net.CIDRMask(24, 32)},
			},
		},
	}
	p2 := &Peer{
		Name: "2",
		Peer: wireguard.Peer{
			PublicKey: []byte("key2"),
			AllowedIPs: []*net.IPNet{
				{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)},
				{IP: net.ParseIP("10.0.0.3"), Mask: net.CIDRMask(24, 32)},
			},
		},
	}
	p3 := &Peer{
		Name: "3",
		Peer: wireguard.Peer{
			PublicKey: []byte("key3"),
			AllowedIPs: []*net.IPNet{
				{IP: net.ParseIP("10.0.0.2"), Mask: net.CIDRMask(24, 32)},
				{IP: net.ParseIP("10.0.0.3"), Mask: net.CIDRMask(24, 32)},
				{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)},
			},
		},
	}

	p4 := &Peer{
		Name: "4",
		Peer: wireguard.Peer{
			PublicKey: []byte("key4"),
			AllowedIPs: []*net.IPNet{
				{IP: net.ParseIP("10.0.0.3"), Mask: net.CIDRMask(24, 32)},
				{IP: net.ParseIP("10.0.0.3"), Mask: net.CIDRMask(24, 32)},
			},
		},
	}

	for _, tc := range []struct {
		name  string
		peers []*Peer
		out   []*Peer
	}{
		{
			name:  "nil",
			peers: nil,
			out:   nil,
		},
		{
			name:  "simple dupe",
			peers: []*Peer{p1, p2},
			out: []*Peer{
				p1,
				{
					Name: "2",
					Peer: wireguard.Peer{
						PublicKey: []byte("key2"),
						AllowedIPs: []*net.IPNet{
							{IP: net.ParseIP("10.0.0.3"), Mask: net.CIDRMask(24, 32)},
						},
					},
				},
			},
		},
		{
			name:  "simple dupe reversed",
			peers: []*Peer{p2, p1},
			out: []*Peer{
				p2,
				{
					Name: "1",
					Peer: wireguard.Peer{
						PublicKey: []byte("key1"),
						AllowedIPs: []*net.IPNet{
							{IP: net.ParseIP("10.0.0.2"), Mask: net.CIDRMask(24, 32)},
						},
					},
				},
			},
		},
		{
			name:  "one duplicates all",
			peers: []*Peer{p3, p2, p1, p4},
			out: []*Peer{
				p3,
				{
					Name: "2",
					Peer: wireguard.Peer{
						PublicKey: []byte("key2"),
					},
				},
				{
					Name: "1",
					Peer: wireguard.Peer{
						PublicKey: []byte("key1"),
					},
				},
				{
					Name: "4",
					Peer: wireguard.Peer{
						PublicKey: []byte("key4"),
					},
				},
			},
		},
		{
			name:  "one duplicates itself",
			peers: []*Peer{p4, p1},
			out: []*Peer{
				{
					Name: "4",
					Peer: wireguard.Peer{
						PublicKey: []byte("key4"),
						AllowedIPs: []*net.IPNet{
							{IP: net.ParseIP("10.0.0.3"), Mask: net.CIDRMask(24, 32)},
						},
					},
				},
				{
					Name: "1",
					Peer: wireguard.Peer{
						PublicKey: []byte("key1"),
						AllowedIPs: []*net.IPNet{
							{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)},
							{IP: net.ParseIP("10.0.0.2"), Mask: net.CIDRMask(24, 32)},
						},
					},
				},
			},
		},
	} {
		out := deduplicatePeerIPs(tc.peers)
		if diff := pretty.Compare(out, tc.out); diff != "" {
			t.Errorf("test case %q: got diff: %v", tc.name, diff)
		}
	}
}
