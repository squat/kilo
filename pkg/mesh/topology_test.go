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
	"testing"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/kylelemons/godebug/pretty"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/squat/kilo/pkg/wireguard"
)

func mustParseCIDR(s string) (r net.IPNet) {
	if _, ip, err := net.ParseCIDR(s); err != nil {
		panic("failed to parse CIDR")
	} else {
		r = *ip
	}
	return
}

var (
	key1 = wgtypes.Key{'k', 'e', 'y', '1'}
	key2 = wgtypes.Key{'k', 'e', 'y', '2'}
	key3 = wgtypes.Key{'k', 'e', 'y', '3'}
	key4 = wgtypes.Key{'k', 'e', 'y', '4'}
	key5 = wgtypes.Key{'k', 'e', 'y', '5'}
)

func setup(t *testing.T) (map[string]*Node, map[string]*Peer, wgtypes.Key, int) {
	key := wgtypes.Key{'p', 'r', 'i', 'v'}
	e1 := &net.IPNet{IP: net.ParseIP("10.1.0.1").To4(), Mask: net.CIDRMask(16, 32)}
	e2 := &net.IPNet{IP: net.ParseIP("10.1.0.2").To4(), Mask: net.CIDRMask(16, 32)}
	e3 := &net.IPNet{IP: net.ParseIP("10.1.0.3").To4(), Mask: net.CIDRMask(16, 32)}
	e4 := &net.IPNet{IP: net.ParseIP("10.1.0.4").To4(), Mask: net.CIDRMask(16, 32)}
	i1 := &net.IPNet{IP: net.ParseIP("192.168.0.1").To4(), Mask: net.CIDRMask(32, 32)}
	i2 := &net.IPNet{IP: net.ParseIP("192.168.0.2").To4(), Mask: net.CIDRMask(32, 32)}
	i3 := &net.IPNet{IP: net.ParseIP("192.168.178.3").To4(), Mask: net.CIDRMask(32, 32)}
	nodes := map[string]*Node{
		"a": {
			Name:                "a",
			Endpoint:            wireguard.NewEndpoint(e1.IP, DefaultKiloPort),
			InternalIP:          i1,
			Location:            "1",
			Subnet:              &net.IPNet{IP: net.ParseIP("10.2.1.0"), Mask: net.CIDRMask(24, 32)},
			Key:                 key1,
			PersistentKeepalive: 25,
		},
		"b": {
			Name:               "b",
			Endpoint:           wireguard.NewEndpoint(e2.IP, DefaultKiloPort),
			InternalIP:         i1,
			Location:           "2",
			Subnet:             &net.IPNet{IP: net.ParseIP("10.2.2.0"), Mask: net.CIDRMask(24, 32)},
			Key:                key2,
			AllowedLocationIPs: []net.IPNet{*i3},
		},
		"c": {
			Name:       "c",
			Endpoint:   wireguard.NewEndpoint(e3.IP, DefaultKiloPort),
			InternalIP: i2,
			// Same location as node b.
			Location: "2",
			Subnet:   &net.IPNet{IP: net.ParseIP("10.2.3.0"), Mask: net.CIDRMask(24, 32)},
			Key:      key3,
		},
		"d": {
			Name:     "d",
			Endpoint: wireguard.NewEndpoint(e4.IP, DefaultKiloPort),
			// Same location as node a, but without private IP
			Location: "1",
			Subnet:   &net.IPNet{IP: net.ParseIP("10.2.4.0"), Mask: net.CIDRMask(24, 32)},
			Key:      key4,
		},
	}
	peers := map[string]*Peer{
		"a": {
			Name: "a",
			Peer: wireguard.Peer{
				PeerConfig: wgtypes.PeerConfig{
					AllowedIPs: []net.IPNet{
						{IP: net.ParseIP("10.5.0.1"), Mask: net.CIDRMask(24, 32)},
						{IP: net.ParseIP("10.5.0.2"), Mask: net.CIDRMask(24, 32)},
					},
					PublicKey: key4,
				},
			},
		},
		"b": {
			Name: "b",
			Peer: wireguard.Peer{
				PeerConfig: wgtypes.PeerConfig{
					AllowedIPs: []net.IPNet{
						{IP: net.ParseIP("10.5.0.3"), Mask: net.CIDRMask(24, 32)},
					},
					PublicKey: key5,
				},
				Endpoint: wireguard.NewEndpoint(net.ParseIP("192.168.0.1"), DefaultKiloPort),
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
	w4 := net.ParseIP("10.4.0.4").To4()
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
				location:      logicalLocationPrefix + nodes["a"].Location,
				subnet:        nodes["a"].Subnet,
				privateIP:     nodes["a"].InternalIP,
				wireGuardCIDR: &net.IPNet{IP: w1, Mask: net.CIDRMask(16, 32)},
				segments: []*segment{
					{
						allowedIPs:          []net.IPNet{*nodes["a"].Subnet, *nodes["a"].InternalIP, {IP: w1, Mask: net.CIDRMask(32, 32)}},
						endpoint:            nodes["a"].Endpoint,
						key:                 nodes["a"].Key,
						persistentKeepalive: nodes["a"].PersistentKeepalive,
						location:            logicalLocationPrefix + nodes["a"].Location,
						cidrs:               []*net.IPNet{nodes["a"].Subnet},
						hostnames:           []string{"a"},
						privateIPs:          []net.IP{nodes["a"].InternalIP.IP},
						wireGuardIP:         w1,
					},
					{
						allowedIPs:          []net.IPNet{*nodes["b"].Subnet, *nodes["b"].InternalIP, *nodes["c"].Subnet, *nodes["c"].InternalIP, {IP: w2, Mask: net.CIDRMask(32, 32)}},
						endpoint:            nodes["b"].Endpoint,
						key:                 nodes["b"].Key,
						persistentKeepalive: nodes["b"].PersistentKeepalive,
						location:            logicalLocationPrefix + nodes["b"].Location,
						cidrs:               []*net.IPNet{nodes["b"].Subnet, nodes["c"].Subnet},
						hostnames:           []string{"b", "c"},
						privateIPs:          []net.IP{nodes["b"].InternalIP.IP, nodes["c"].InternalIP.IP},
						wireGuardIP:         w2,
						allowedLocationIPs:  nodes["b"].AllowedLocationIPs,
					},
					{
						allowedIPs:          []net.IPNet{*nodes["d"].Subnet, {IP: w3, Mask: net.CIDRMask(32, 32)}},
						endpoint:            nodes["d"].Endpoint,
						key:                 nodes["d"].Key,
						persistentKeepalive: nodes["d"].PersistentKeepalive,
						location:            nodeLocationPrefix + nodes["d"].Name,
						cidrs:               []*net.IPNet{nodes["d"].Subnet},
						hostnames:           []string{"d"},
						privateIPs:          nil,
						wireGuardIP:         w3,
					},
				},
				peers:  []*Peer{peers["a"], peers["b"]},
				logger: log.NewNopLogger(),
			},
		},
		{
			name:        "logical from b",
			granularity: LogicalGranularity,
			hostname:    nodes["b"].Name,
			result: &Topology{
				hostname:      nodes["b"].Name,
				leader:        true,
				location:      logicalLocationPrefix + nodes["b"].Location,
				subnet:        nodes["b"].Subnet,
				privateIP:     nodes["b"].InternalIP,
				wireGuardCIDR: &net.IPNet{IP: w2, Mask: net.CIDRMask(16, 32)},
				segments: []*segment{
					{
						allowedIPs:          []net.IPNet{*nodes["a"].Subnet, *nodes["a"].InternalIP, {IP: w1, Mask: net.CIDRMask(32, 32)}},
						endpoint:            nodes["a"].Endpoint,
						key:                 nodes["a"].Key,
						persistentKeepalive: nodes["a"].PersistentKeepalive,
						location:            logicalLocationPrefix + nodes["a"].Location,
						cidrs:               []*net.IPNet{nodes["a"].Subnet},
						hostnames:           []string{"a"},
						privateIPs:          []net.IP{nodes["a"].InternalIP.IP},
						wireGuardIP:         w1,
					},
					{
						allowedIPs:          []net.IPNet{*nodes["b"].Subnet, *nodes["b"].InternalIP, *nodes["c"].Subnet, *nodes["c"].InternalIP, {IP: w2, Mask: net.CIDRMask(32, 32)}},
						endpoint:            nodes["b"].Endpoint,
						key:                 nodes["b"].Key,
						persistentKeepalive: nodes["b"].PersistentKeepalive,
						location:            logicalLocationPrefix + nodes["b"].Location,
						cidrs:               []*net.IPNet{nodes["b"].Subnet, nodes["c"].Subnet},
						hostnames:           []string{"b", "c"},
						privateIPs:          []net.IP{nodes["b"].InternalIP.IP, nodes["c"].InternalIP.IP},
						wireGuardIP:         w2,
						allowedLocationIPs:  nodes["b"].AllowedLocationIPs,
					},
					{
						allowedIPs:          []net.IPNet{*nodes["d"].Subnet, {IP: w3, Mask: net.CIDRMask(32, 32)}},
						endpoint:            nodes["d"].Endpoint,
						key:                 nodes["d"].Key,
						persistentKeepalive: nodes["d"].PersistentKeepalive,
						location:            nodeLocationPrefix + nodes["d"].Name,
						cidrs:               []*net.IPNet{nodes["d"].Subnet},
						hostnames:           []string{"d"},
						privateIPs:          nil,
						wireGuardIP:         w3,
					},
				},
				peers:  []*Peer{peers["a"], peers["b"]},
				logger: log.NewNopLogger(),
			},
		},
		{
			name:        "logical from c",
			granularity: LogicalGranularity,
			hostname:    nodes["c"].Name,
			result: &Topology{
				hostname:      nodes["c"].Name,
				leader:        false,
				location:      logicalLocationPrefix + nodes["b"].Location,
				subnet:        nodes["c"].Subnet,
				privateIP:     nodes["c"].InternalIP,
				wireGuardCIDR: DefaultKiloSubnet,
				segments: []*segment{
					{
						allowedIPs:          []net.IPNet{*nodes["a"].Subnet, *nodes["a"].InternalIP, {IP: w1, Mask: net.CIDRMask(32, 32)}},
						endpoint:            nodes["a"].Endpoint,
						key:                 nodes["a"].Key,
						persistentKeepalive: nodes["a"].PersistentKeepalive,
						location:            logicalLocationPrefix + nodes["a"].Location,
						cidrs:               []*net.IPNet{nodes["a"].Subnet},
						hostnames:           []string{"a"},
						privateIPs:          []net.IP{nodes["a"].InternalIP.IP},
						wireGuardIP:         w1,
					},
					{
						allowedIPs:          []net.IPNet{*nodes["b"].Subnet, *nodes["b"].InternalIP, *nodes["c"].Subnet, *nodes["c"].InternalIP, {IP: w2, Mask: net.CIDRMask(32, 32)}},
						endpoint:            nodes["b"].Endpoint,
						key:                 nodes["b"].Key,
						persistentKeepalive: nodes["b"].PersistentKeepalive,
						location:            logicalLocationPrefix + nodes["b"].Location,
						cidrs:               []*net.IPNet{nodes["b"].Subnet, nodes["c"].Subnet},
						hostnames:           []string{"b", "c"},
						privateIPs:          []net.IP{nodes["b"].InternalIP.IP, nodes["c"].InternalIP.IP},
						wireGuardIP:         w2,
						allowedLocationIPs:  nodes["b"].AllowedLocationIPs,
					},
					{
						allowedIPs:          []net.IPNet{*nodes["d"].Subnet, {IP: w3, Mask: net.CIDRMask(32, 32)}},
						endpoint:            nodes["d"].Endpoint,
						key:                 nodes["d"].Key,
						persistentKeepalive: nodes["d"].PersistentKeepalive,
						location:            nodeLocationPrefix + nodes["d"].Name,
						cidrs:               []*net.IPNet{nodes["d"].Subnet},
						hostnames:           []string{"d"},
						privateIPs:          nil,
						wireGuardIP:         w3,
					},
				},
				peers:  []*Peer{peers["a"], peers["b"]},
				logger: log.NewNopLogger(),
			},
		},
		{
			name:        "full from a",
			granularity: FullGranularity,
			hostname:    nodes["a"].Name,
			result: &Topology{
				hostname:      nodes["a"].Name,
				leader:        true,
				location:      nodeLocationPrefix + nodes["a"].Name,
				subnet:        nodes["a"].Subnet,
				privateIP:     nodes["a"].InternalIP,
				wireGuardCIDR: &net.IPNet{IP: w1, Mask: net.CIDRMask(16, 32)},
				segments: []*segment{
					{
						allowedIPs:          []net.IPNet{*nodes["a"].Subnet, *nodes["a"].InternalIP, {IP: w1, Mask: net.CIDRMask(32, 32)}},
						endpoint:            nodes["a"].Endpoint,
						key:                 nodes["a"].Key,
						persistentKeepalive: nodes["a"].PersistentKeepalive,
						location:            nodeLocationPrefix + nodes["a"].Name,
						cidrs:               []*net.IPNet{nodes["a"].Subnet},
						hostnames:           []string{"a"},
						privateIPs:          []net.IP{nodes["a"].InternalIP.IP},
						wireGuardIP:         w1,
					},
					{
						allowedIPs:          []net.IPNet{*nodes["b"].Subnet, *nodes["b"].InternalIP, {IP: w2, Mask: net.CIDRMask(32, 32)}},
						endpoint:            nodes["b"].Endpoint,
						key:                 nodes["b"].Key,
						persistentKeepalive: nodes["b"].PersistentKeepalive,
						location:            nodeLocationPrefix + nodes["b"].Name,
						cidrs:               []*net.IPNet{nodes["b"].Subnet},
						hostnames:           []string{"b"},
						privateIPs:          []net.IP{nodes["b"].InternalIP.IP},
						wireGuardIP:         w2,
						allowedLocationIPs:  nodes["b"].AllowedLocationIPs,
					},
					{
						allowedIPs:          []net.IPNet{*nodes["c"].Subnet, *nodes["c"].InternalIP, {IP: w3, Mask: net.CIDRMask(32, 32)}},
						endpoint:            nodes["c"].Endpoint,
						key:                 nodes["c"].Key,
						persistentKeepalive: nodes["c"].PersistentKeepalive,
						location:            nodeLocationPrefix + nodes["c"].Name,
						cidrs:               []*net.IPNet{nodes["c"].Subnet},
						hostnames:           []string{"c"},
						privateIPs:          []net.IP{nodes["c"].InternalIP.IP},
						wireGuardIP:         w3,
					},
					{
						allowedIPs:          []net.IPNet{*nodes["d"].Subnet, {IP: w4, Mask: net.CIDRMask(32, 32)}},
						endpoint:            nodes["d"].Endpoint,
						key:                 nodes["d"].Key,
						persistentKeepalive: nodes["d"].PersistentKeepalive,
						location:            nodeLocationPrefix + nodes["d"].Name,
						cidrs:               []*net.IPNet{nodes["d"].Subnet},
						hostnames:           []string{"d"},
						privateIPs:          nil,
						wireGuardIP:         w4,
					},
				},
				peers:  []*Peer{peers["a"], peers["b"]},
				logger: log.NewNopLogger(),
			},
		},
		{
			name:        "full from b",
			granularity: FullGranularity,
			hostname:    nodes["b"].Name,
			result: &Topology{
				hostname:      nodes["b"].Name,
				leader:        true,
				location:      nodeLocationPrefix + nodes["b"].Name,
				subnet:        nodes["b"].Subnet,
				privateIP:     nodes["b"].InternalIP,
				wireGuardCIDR: &net.IPNet{IP: w2, Mask: net.CIDRMask(16, 32)},
				segments: []*segment{
					{
						allowedIPs:          []net.IPNet{*nodes["a"].Subnet, *nodes["a"].InternalIP, {IP: w1, Mask: net.CIDRMask(32, 32)}},
						endpoint:            nodes["a"].Endpoint,
						key:                 nodes["a"].Key,
						persistentKeepalive: nodes["a"].PersistentKeepalive,
						location:            nodeLocationPrefix + nodes["a"].Name,
						cidrs:               []*net.IPNet{nodes["a"].Subnet},
						hostnames:           []string{"a"},
						privateIPs:          []net.IP{nodes["a"].InternalIP.IP},
						wireGuardIP:         w1,
					},
					{
						allowedIPs:          []net.IPNet{*nodes["b"].Subnet, *nodes["b"].InternalIP, {IP: w2, Mask: net.CIDRMask(32, 32)}},
						endpoint:            nodes["b"].Endpoint,
						key:                 nodes["b"].Key,
						persistentKeepalive: nodes["b"].PersistentKeepalive,
						location:            nodeLocationPrefix + nodes["b"].Name,
						cidrs:               []*net.IPNet{nodes["b"].Subnet},
						hostnames:           []string{"b"},
						privateIPs:          []net.IP{nodes["b"].InternalIP.IP},
						wireGuardIP:         w2,
						allowedLocationIPs:  nodes["b"].AllowedLocationIPs,
					},
					{
						allowedIPs:          []net.IPNet{*nodes["c"].Subnet, *nodes["c"].InternalIP, {IP: w3, Mask: net.CIDRMask(32, 32)}},
						endpoint:            nodes["c"].Endpoint,
						key:                 nodes["c"].Key,
						persistentKeepalive: nodes["c"].PersistentKeepalive,
						location:            nodeLocationPrefix + nodes["c"].Name,
						cidrs:               []*net.IPNet{nodes["c"].Subnet},
						hostnames:           []string{"c"},
						privateIPs:          []net.IP{nodes["c"].InternalIP.IP},
						wireGuardIP:         w3,
					},
					{
						allowedIPs:          []net.IPNet{*nodes["d"].Subnet, {IP: w4, Mask: net.CIDRMask(32, 32)}},
						endpoint:            nodes["d"].Endpoint,
						key:                 nodes["d"].Key,
						persistentKeepalive: nodes["d"].PersistentKeepalive,
						location:            nodeLocationPrefix + nodes["d"].Name,
						cidrs:               []*net.IPNet{nodes["d"].Subnet},
						hostnames:           []string{"d"},
						privateIPs:          nil,
						wireGuardIP:         w4,
					},
				},
				peers:  []*Peer{peers["a"], peers["b"]},
				logger: log.NewNopLogger(),
			},
		},
		{
			name:        "full from c",
			granularity: FullGranularity,
			hostname:    nodes["c"].Name,
			result: &Topology{
				hostname:      nodes["c"].Name,
				leader:        true,
				location:      nodeLocationPrefix + nodes["c"].Name,
				subnet:        nodes["c"].Subnet,
				privateIP:     nodes["c"].InternalIP,
				wireGuardCIDR: &net.IPNet{IP: w3, Mask: net.CIDRMask(16, 32)},
				segments: []*segment{
					{
						allowedIPs:          []net.IPNet{*nodes["a"].Subnet, *nodes["a"].InternalIP, {IP: w1, Mask: net.CIDRMask(32, 32)}},
						endpoint:            nodes["a"].Endpoint,
						key:                 nodes["a"].Key,
						persistentKeepalive: nodes["a"].PersistentKeepalive,
						location:            nodeLocationPrefix + nodes["a"].Name,
						cidrs:               []*net.IPNet{nodes["a"].Subnet},
						hostnames:           []string{"a"},
						privateIPs:          []net.IP{nodes["a"].InternalIP.IP},
						wireGuardIP:         w1,
					},
					{
						allowedIPs:          []net.IPNet{*nodes["b"].Subnet, *nodes["b"].InternalIP, {IP: w2, Mask: net.CIDRMask(32, 32)}},
						endpoint:            nodes["b"].Endpoint,
						key:                 nodes["b"].Key,
						persistentKeepalive: nodes["b"].PersistentKeepalive,
						location:            nodeLocationPrefix + nodes["b"].Name,
						cidrs:               []*net.IPNet{nodes["b"].Subnet},
						hostnames:           []string{"b"},
						privateIPs:          []net.IP{nodes["b"].InternalIP.IP},
						wireGuardIP:         w2,
						allowedLocationIPs:  nodes["b"].AllowedLocationIPs,
					},
					{
						allowedIPs:          []net.IPNet{*nodes["c"].Subnet, *nodes["c"].InternalIP, {IP: w3, Mask: net.CIDRMask(32, 32)}},
						endpoint:            nodes["c"].Endpoint,
						key:                 nodes["c"].Key,
						persistentKeepalive: nodes["c"].PersistentKeepalive,
						location:            nodeLocationPrefix + nodes["c"].Name,
						cidrs:               []*net.IPNet{nodes["c"].Subnet},
						hostnames:           []string{"c"},
						privateIPs:          []net.IP{nodes["c"].InternalIP.IP},
						wireGuardIP:         w3,
					},
					{
						allowedIPs:          []net.IPNet{*nodes["d"].Subnet, {IP: w4, Mask: net.CIDRMask(32, 32)}},
						endpoint:            nodes["d"].Endpoint,
						key:                 nodes["d"].Key,
						persistentKeepalive: nodes["d"].PersistentKeepalive,
						location:            nodeLocationPrefix + nodes["d"].Name,
						cidrs:               []*net.IPNet{nodes["d"].Subnet},
						hostnames:           []string{"d"},
						privateIPs:          nil,
						wireGuardIP:         w4,
					},
				},
				peers:  []*Peer{peers["a"], peers["b"]},
				logger: log.NewNopLogger(),
			},
		},
		{
			name:        "full from d",
			granularity: FullGranularity,
			hostname:    nodes["d"].Name,
			result: &Topology{
				hostname:      nodes["d"].Name,
				leader:        true,
				location:      nodeLocationPrefix + nodes["d"].Name,
				subnet:        nodes["d"].Subnet,
				privateIP:     nil,
				wireGuardCIDR: &net.IPNet{IP: w4, Mask: net.CIDRMask(16, 32)},
				segments: []*segment{
					{
						allowedIPs:          []net.IPNet{*nodes["a"].Subnet, *nodes["a"].InternalIP, {IP: w1, Mask: net.CIDRMask(32, 32)}},
						endpoint:            nodes["a"].Endpoint,
						key:                 nodes["a"].Key,
						persistentKeepalive: nodes["a"].PersistentKeepalive,
						location:            nodeLocationPrefix + nodes["a"].Name,
						cidrs:               []*net.IPNet{nodes["a"].Subnet},
						hostnames:           []string{"a"},
						privateIPs:          []net.IP{nodes["a"].InternalIP.IP},
						wireGuardIP:         w1,
					},
					{
						allowedIPs:          []net.IPNet{*nodes["b"].Subnet, *nodes["b"].InternalIP, {IP: w2, Mask: net.CIDRMask(32, 32)}},
						endpoint:            nodes["b"].Endpoint,
						key:                 nodes["b"].Key,
						persistentKeepalive: nodes["b"].PersistentKeepalive,
						location:            nodeLocationPrefix + nodes["b"].Name,
						cidrs:               []*net.IPNet{nodes["b"].Subnet},
						hostnames:           []string{"b"},
						privateIPs:          []net.IP{nodes["b"].InternalIP.IP},
						wireGuardIP:         w2,
						allowedLocationIPs:  nodes["b"].AllowedLocationIPs,
					},
					{
						allowedIPs:          []net.IPNet{*nodes["c"].Subnet, *nodes["c"].InternalIP, {IP: w3, Mask: net.CIDRMask(32, 32)}},
						endpoint:            nodes["c"].Endpoint,
						key:                 nodes["c"].Key,
						persistentKeepalive: nodes["c"].PersistentKeepalive,
						location:            nodeLocationPrefix + nodes["c"].Name,
						cidrs:               []*net.IPNet{nodes["c"].Subnet},
						hostnames:           []string{"c"},
						privateIPs:          []net.IP{nodes["c"].InternalIP.IP},
						wireGuardIP:         w3,
					},
					{
						allowedIPs:          []net.IPNet{*nodes["d"].Subnet, {IP: w4, Mask: net.CIDRMask(32, 32)}},
						endpoint:            nodes["d"].Endpoint,
						key:                 nodes["d"].Key,
						persistentKeepalive: nodes["d"].PersistentKeepalive,
						location:            nodeLocationPrefix + nodes["d"].Name,
						cidrs:               []*net.IPNet{nodes["d"].Subnet},
						hostnames:           []string{"d"},
						privateIPs:          nil,
						wireGuardIP:         w4,
					},
				},
				peers:  []*Peer{peers["a"], peers["b"]},
				logger: log.NewNopLogger(),
			},
		},
	} {
		tc.result.key = key
		tc.result.port = port
		topo, err := NewTopology(nodes, peers, tc.granularity, tc.hostname, port, key, DefaultKiloSubnet, nil, 0, nil)
		if err != nil {
			t.Errorf("test case %q: failed to generate Topology: %v", tc.name, err)
		}
		if diff := pretty.Compare(topo, tc.result); diff != "" {
			t.Errorf("test case %q: got diff: %v", tc.name, diff)
		}
	}
}

func mustTopo(t *testing.T, nodes map[string]*Node, peers map[string]*Peer, granularity Granularity, hostname string, port int, key wgtypes.Key, subnet *net.IPNet, persistentKeepalive time.Duration) *Topology {
	topo, err := NewTopology(nodes, peers, granularity, hostname, port, key, subnet, nil, persistentKeepalive, nil)
	if err != nil {
		t.Errorf("failed to generate Topology: %v", err)
	}
	return topo
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
			Name:     "a",
			Endpoint: wireguard.NewEndpoint(e1.IP, DefaultKiloPort),
		},
		{
			Name:     "b",
			Endpoint: wireguard.NewEndpoint(e2.IP, DefaultKiloPort),
		},
		{
			Name:     "c",
			Endpoint: wireguard.NewEndpoint(e2.IP, DefaultKiloPort),
		},
		{
			Name:     "d",
			Endpoint: wireguard.NewEndpoint(e1.IP, DefaultKiloPort),
			Leader:   true,
		},
		{
			Name:     "2",
			Endpoint: wireguard.NewEndpoint(e2.IP, DefaultKiloPort),
			Leader:   true,
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
			PeerConfig: wgtypes.PeerConfig{

				PublicKey: key1,
				AllowedIPs: []net.IPNet{
					{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)},
					{IP: net.ParseIP("10.0.0.2"), Mask: net.CIDRMask(24, 32)},
				},
			},
		},
	}
	p2 := &Peer{
		Name: "2",
		Peer: wireguard.Peer{
			PeerConfig: wgtypes.PeerConfig{
				PublicKey: key2,
				AllowedIPs: []net.IPNet{
					{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)},
					{IP: net.ParseIP("10.0.0.3"), Mask: net.CIDRMask(24, 32)},
				},
			},
		},
	}
	p3 := &Peer{
		Name: "3",
		Peer: wireguard.Peer{
			PeerConfig: wgtypes.PeerConfig{
				PublicKey: key3,
				AllowedIPs: []net.IPNet{
					{IP: net.ParseIP("10.0.0.2"), Mask: net.CIDRMask(24, 32)},
					{IP: net.ParseIP("10.0.0.3"), Mask: net.CIDRMask(24, 32)},
					{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)},
				},
			},
		},
	}

	p4 := &Peer{
		Name: "4",
		Peer: wireguard.Peer{
			PeerConfig: wgtypes.PeerConfig{
				PublicKey: key4,
				AllowedIPs: []net.IPNet{
					{IP: net.ParseIP("10.0.0.3"), Mask: net.CIDRMask(24, 32)},
					{IP: net.ParseIP("10.0.0.3"), Mask: net.CIDRMask(24, 32)},
				},
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
						PeerConfig: wgtypes.PeerConfig{
							PublicKey: key2,
							AllowedIPs: []net.IPNet{
								{IP: net.ParseIP("10.0.0.3"), Mask: net.CIDRMask(24, 32)},
							},
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
						PeerConfig: wgtypes.PeerConfig{
							PublicKey: key1,
							AllowedIPs: []net.IPNet{
								{IP: net.ParseIP("10.0.0.2"), Mask: net.CIDRMask(24, 32)},
							},
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
						PeerConfig: wgtypes.PeerConfig{
							PublicKey: key2,
						},
					},
				},
				{
					Name: "1",
					Peer: wireguard.Peer{
						PeerConfig: wgtypes.PeerConfig{
							PublicKey: key1,
						},
					},
				},
				{
					Name: "4",
					Peer: wireguard.Peer{
						PeerConfig: wgtypes.PeerConfig{
							PublicKey: key4,
						},
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
						PeerConfig: wgtypes.PeerConfig{
							PublicKey: key4,
							AllowedIPs: []net.IPNet{
								{IP: net.ParseIP("10.0.0.3"), Mask: net.CIDRMask(24, 32)},
							},
						},
					},
				},
				{
					Name: "1",
					Peer: wireguard.Peer{
						PeerConfig: wgtypes.PeerConfig{
							PublicKey: key1,
							AllowedIPs: []net.IPNet{
								{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)},
								{IP: net.ParseIP("10.0.0.2"), Mask: net.CIDRMask(24, 32)},
							},
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

func TestFilterAllowedIPs(t *testing.T) {
	nodes, peers, key, port := setup(t)
	topo := mustTopo(t, nodes, peers, LogicalGranularity, nodes["a"].Name, port, key, DefaultKiloSubnet, nodes["a"].PersistentKeepalive)
	for _, tc := range []struct {
		name               string
		allowedLocationIPs map[int][]net.IPNet
		result             map[int][]net.IPNet
	}{
		{
			name: "nothing to filter",
			allowedLocationIPs: map[int][]net.IPNet{
				0: {
					mustParseCIDR("192.168.178.4/32"),
				},
				1: {
					mustParseCIDR("192.168.178.5/32"),
				},
				2: {
					mustParseCIDR("192.168.178.6/32"),
					mustParseCIDR("192.168.178.7/32"),
				},
			},
			result: map[int][]net.IPNet{
				0: {
					mustParseCIDR("192.168.178.4/32"),
				},
				1: {
					mustParseCIDR("192.168.178.5/32"),
				},
				2: {
					mustParseCIDR("192.168.178.6/32"),
					mustParseCIDR("192.168.178.7/32"),
				},
			},
		},
		{
			name: "intersections between segments",
			allowedLocationIPs: map[int][]net.IPNet{
				0: {
					mustParseCIDR("192.168.178.4/32"),
					mustParseCIDR("192.168.178.8/32"),
				},
				1: {
					mustParseCIDR("192.168.178.5/32"),
				},
				2: {
					mustParseCIDR("192.168.178.6/32"),
					mustParseCIDR("192.168.178.7/32"),
					mustParseCIDR("192.168.178.4/32"),
				},
			},
			result: map[int][]net.IPNet{
				0: {
					mustParseCIDR("192.168.178.8/32"),
				},
				1: {
					mustParseCIDR("192.168.178.5/32"),
				},
				2: {
					mustParseCIDR("192.168.178.6/32"),
					mustParseCIDR("192.168.178.7/32"),
					mustParseCIDR("192.168.178.4/32"),
				},
			},
		},
		{
			name: "intersections with wireGuardCIDR",
			allowedLocationIPs: map[int][]net.IPNet{
				0: {
					mustParseCIDR("10.4.0.1/32"),
					mustParseCIDR("192.168.178.8/32"),
				},
				1: {
					mustParseCIDR("192.168.178.5/32"),
				},
				2: {
					mustParseCIDR("192.168.178.6/32"),
					mustParseCIDR("192.168.178.7/32"),
				},
			},
			result: map[int][]net.IPNet{
				0: {
					mustParseCIDR("192.168.178.8/32"),
				},
				1: {
					mustParseCIDR("192.168.178.5/32"),
				},
				2: {
					mustParseCIDR("192.168.178.6/32"),
					mustParseCIDR("192.168.178.7/32"),
				},
			},
		},
		{
			name: "intersections with more than one allowedLocationIPs",
			allowedLocationIPs: map[int][]net.IPNet{
				0: {
					mustParseCIDR("192.168.178.8/32"),
				},
				1: {
					mustParseCIDR("192.168.178.5/32"),
				},
				2: {
					mustParseCIDR("192.168.178.7/24"),
				},
			},
			result: map[int][]net.IPNet{
				0: {},
				1: {},
				2: {
					mustParseCIDR("192.168.178.7/24"),
				},
			},
		},
	} {
		for k, v := range tc.allowedLocationIPs {
			topo.segments[k].allowedLocationIPs = v
		}
		for k, v := range topo.segments {
			f := topo.filterAllowedLocationIPs(v.allowedLocationIPs, v.location)
			// Overwrite the allowedLocationIPs to mimic the actual usage of the filterAllowedLocationIPs function.
			topo.segments[k].allowedLocationIPs = f
			if !ipNetSlicesEqual(f, tc.result[k]) {
				t.Errorf("test case %q:\n\texpected:\n\t%q\n\tgot:\n\t%q\n", tc.name, tc.result[k], f)
			}
		}

	}
}
