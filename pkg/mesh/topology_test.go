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
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func allowedIPs(ips ...string) string {
	return strings.Join(ips, ", ")
}

func setup(t *testing.T) (map[string]*Node, []byte, int, *net.IPNet) {
	key := []byte("private")
	port := 51820
	_, kiloNet, err := net.ParseCIDR("10.4.0.0/16")
	if err != nil {
		t.Fatalf("failed to parse Kilo subnet CIDR: %v", err)
	}
	ip, e1, err := net.ParseCIDR("10.1.0.1/16")
	if err != nil {
		t.Fatalf("failed to parse external IP CIDR: %v", err)
	}
	e1.IP = ip
	ip, e2, err := net.ParseCIDR("10.1.0.2/16")
	if err != nil {
		t.Fatalf("failed to parse external IP CIDR: %v", err)
	}
	e2.IP = ip
	ip, e3, err := net.ParseCIDR("10.1.0.3/16")
	if err != nil {
		t.Fatalf("failed to parse external IP CIDR: %v", err)
	}
	e3.IP = ip
	ip, i1, err := net.ParseCIDR("192.168.0.1/24")
	if err != nil {
		t.Fatalf("failed to parse internal IP CIDR: %v", err)
	}
	i1.IP = ip
	ip, i2, err := net.ParseCIDR("192.168.0.2/24")
	if err != nil {
		t.Fatalf("failed to parse internal IP CIDR: %v", err)
	}
	i2.IP = ip
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
	return nodes, key, port, kiloNet
}

func TestNewTopology(t *testing.T) {
	nodes, key, port, kiloNet := setup(t)

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
			name:        "datacenter from a",
			granularity: DataCenterGranularity,
			hostname:    nodes["a"].Name,
			result: &Topology{
				hostname:      nodes["a"].Name,
				leader:        true,
				Location:      nodes["a"].Location,
				subnet:        kiloNet,
				privateIP:     nodes["a"].InternalIP,
				wireGuardCIDR: &net.IPNet{IP: w1, Mask: net.CIDRMask(16, 32)},
				Segments: []*segment{
					{
						AllowedIPs:  allowedIPs(nodes["a"].Subnet.String(), "192.168.0.1/32", "10.4.0.1/32"),
						Endpoint:    nodes["a"].ExternalIP.IP.String(),
						Key:         string(nodes["a"].Key),
						Location:    nodes["a"].Location,
						cidrs:       []*net.IPNet{nodes["a"].Subnet},
						hostnames:   []string{"a"},
						privateIPs:  []net.IP{nodes["a"].InternalIP.IP},
						wireGuardIP: w1,
					},
					{
						AllowedIPs:  allowedIPs(nodes["b"].Subnet.String(), "192.168.0.1/32", nodes["c"].Subnet.String(), "192.168.0.2/32", "10.4.0.2/32"),
						Endpoint:    nodes["b"].ExternalIP.IP.String(),
						Key:         string(nodes["b"].Key),
						Location:    nodes["b"].Location,
						cidrs:       []*net.IPNet{nodes["b"].Subnet, nodes["c"].Subnet},
						hostnames:   []string{"b", "c"},
						privateIPs:  []net.IP{nodes["b"].InternalIP.IP, nodes["c"].InternalIP.IP},
						wireGuardIP: w2,
					},
				},
			},
		},
		{
			name:        "datacenter from b",
			granularity: DataCenterGranularity,
			hostname:    nodes["b"].Name,
			result: &Topology{
				hostname:      nodes["b"].Name,
				leader:        true,
				Location:      nodes["b"].Location,
				subnet:        kiloNet,
				privateIP:     nodes["b"].InternalIP,
				wireGuardCIDR: &net.IPNet{IP: w2, Mask: net.CIDRMask(16, 32)},
				Segments: []*segment{
					{
						AllowedIPs:  allowedIPs(nodes["a"].Subnet.String(), "192.168.0.1/32", "10.4.0.1/32"),
						Endpoint:    nodes["a"].ExternalIP.IP.String(),
						Key:         string(nodes["a"].Key),
						Location:    nodes["a"].Location,
						cidrs:       []*net.IPNet{nodes["a"].Subnet},
						hostnames:   []string{"a"},
						privateIPs:  []net.IP{nodes["a"].InternalIP.IP},
						wireGuardIP: w1,
					},
					{
						AllowedIPs:  allowedIPs(nodes["b"].Subnet.String(), "192.168.0.1/32", nodes["c"].Subnet.String(), "192.168.0.2/32", "10.4.0.2/32"),
						Endpoint:    nodes["b"].ExternalIP.IP.String(),
						Key:         string(nodes["b"].Key),
						Location:    nodes["b"].Location,
						cidrs:       []*net.IPNet{nodes["b"].Subnet, nodes["c"].Subnet},
						hostnames:   []string{"b", "c"},
						privateIPs:  []net.IP{nodes["b"].InternalIP.IP, nodes["c"].InternalIP.IP},
						wireGuardIP: w2,
					},
				},
			},
		},
		{
			name:        "datacenter from c",
			granularity: DataCenterGranularity,
			hostname:    nodes["c"].Name,
			result: &Topology{
				hostname:      nodes["c"].Name,
				leader:        false,
				Location:      nodes["b"].Location,
				subnet:        kiloNet,
				privateIP:     nodes["c"].InternalIP,
				wireGuardCIDR: nil,
				Segments: []*segment{
					{
						AllowedIPs:  allowedIPs(nodes["a"].Subnet.String(), "192.168.0.1/32", "10.4.0.1/32"),
						Endpoint:    nodes["a"].ExternalIP.IP.String(),
						Key:         string(nodes["a"].Key),
						Location:    nodes["a"].Location,
						cidrs:       []*net.IPNet{nodes["a"].Subnet},
						hostnames:   []string{"a"},
						privateIPs:  []net.IP{nodes["a"].InternalIP.IP},
						wireGuardIP: w1,
					},
					{
						AllowedIPs:  allowedIPs(nodes["b"].Subnet.String(), "192.168.0.1/32", nodes["c"].Subnet.String(), "192.168.0.2/32", "10.4.0.2/32"),
						Endpoint:    nodes["b"].ExternalIP.IP.String(),
						Key:         string(nodes["b"].Key),
						Location:    nodes["b"].Location,
						cidrs:       []*net.IPNet{nodes["b"].Subnet, nodes["c"].Subnet},
						hostnames:   []string{"b", "c"},
						privateIPs:  []net.IP{nodes["b"].InternalIP.IP, nodes["c"].InternalIP.IP},
						wireGuardIP: w2,
					},
				},
			},
		},
		{
			name:        "node from a",
			granularity: NodeGranularity,
			hostname:    nodes["a"].Name,
			result: &Topology{
				hostname:      nodes["a"].Name,
				leader:        true,
				Location:      nodes["a"].Name,
				subnet:        kiloNet,
				privateIP:     nodes["a"].InternalIP,
				wireGuardCIDR: &net.IPNet{IP: w1, Mask: net.CIDRMask(16, 32)},
				Segments: []*segment{
					{
						AllowedIPs:  allowedIPs(nodes["a"].Subnet.String(), "192.168.0.1/32", "10.4.0.1/32"),
						Endpoint:    nodes["a"].ExternalIP.IP.String(),
						Key:         string(nodes["a"].Key),
						Location:    nodes["a"].Name,
						cidrs:       []*net.IPNet{nodes["a"].Subnet},
						hostnames:   []string{"a"},
						privateIPs:  []net.IP{nodes["a"].InternalIP.IP},
						wireGuardIP: w1,
					},
					{
						AllowedIPs:  allowedIPs(nodes["b"].Subnet.String(), "192.168.0.1/32", "10.4.0.2/32"),
						Endpoint:    nodes["b"].ExternalIP.IP.String(),
						Key:         string(nodes["b"].Key),
						Location:    nodes["b"].Name,
						cidrs:       []*net.IPNet{nodes["b"].Subnet},
						hostnames:   []string{"b"},
						privateIPs:  []net.IP{nodes["b"].InternalIP.IP},
						wireGuardIP: w2,
					},
					{
						AllowedIPs:  allowedIPs(nodes["c"].Subnet.String(), "192.168.0.2/32", "10.4.0.3/32"),
						Endpoint:    nodes["c"].ExternalIP.IP.String(),
						Key:         string(nodes["c"].Key),
						Location:    nodes["c"].Name,
						cidrs:       []*net.IPNet{nodes["c"].Subnet},
						hostnames:   []string{"c"},
						privateIPs:  []net.IP{nodes["c"].InternalIP.IP},
						wireGuardIP: w3,
					},
				},
			},
		},
		{
			name:        "node from b",
			granularity: NodeGranularity,
			hostname:    nodes["b"].Name,
			result: &Topology{
				hostname:      nodes["b"].Name,
				leader:        true,
				Location:      nodes["b"].Name,
				subnet:        kiloNet,
				privateIP:     nodes["b"].InternalIP,
				wireGuardCIDR: &net.IPNet{IP: w2, Mask: net.CIDRMask(16, 32)},
				Segments: []*segment{
					{
						AllowedIPs:  allowedIPs(nodes["a"].Subnet.String(), "192.168.0.1/32", "10.4.0.1/32"),
						Endpoint:    nodes["a"].ExternalIP.IP.String(),
						Key:         string(nodes["a"].Key),
						Location:    nodes["a"].Name,
						cidrs:       []*net.IPNet{nodes["a"].Subnet},
						hostnames:   []string{"a"},
						privateIPs:  []net.IP{nodes["a"].InternalIP.IP},
						wireGuardIP: w1,
					},
					{
						AllowedIPs:  allowedIPs(nodes["b"].Subnet.String(), "192.168.0.1/32", "10.4.0.2/32"),
						Endpoint:    nodes["b"].ExternalIP.IP.String(),
						Key:         string(nodes["b"].Key),
						Location:    nodes["b"].Name,
						cidrs:       []*net.IPNet{nodes["b"].Subnet},
						hostnames:   []string{"b"},
						privateIPs:  []net.IP{nodes["b"].InternalIP.IP},
						wireGuardIP: w2,
					},
					{
						AllowedIPs:  allowedIPs(nodes["c"].Subnet.String(), "192.168.0.2/32", "10.4.0.3/32"),
						Endpoint:    nodes["c"].ExternalIP.IP.String(),
						Key:         string(nodes["c"].Key),
						Location:    nodes["c"].Name,
						cidrs:       []*net.IPNet{nodes["c"].Subnet},
						hostnames:   []string{"c"},
						privateIPs:  []net.IP{nodes["c"].InternalIP.IP},
						wireGuardIP: w3,
					},
				},
			},
		},
		{
			name:        "node from c",
			granularity: NodeGranularity,
			hostname:    nodes["c"].Name,
			result: &Topology{
				hostname:      nodes["c"].Name,
				leader:        true,
				Location:      nodes["c"].Name,
				subnet:        kiloNet,
				privateIP:     nodes["c"].InternalIP,
				wireGuardCIDR: &net.IPNet{IP: w3, Mask: net.CIDRMask(16, 32)},
				Segments: []*segment{
					{
						AllowedIPs:  allowedIPs(nodes["a"].Subnet.String(), "192.168.0.1/32", "10.4.0.1/32"),
						Endpoint:    nodes["a"].ExternalIP.IP.String(),
						Key:         string(nodes["a"].Key),
						Location:    nodes["a"].Name,
						cidrs:       []*net.IPNet{nodes["a"].Subnet},
						hostnames:   []string{"a"},
						privateIPs:  []net.IP{nodes["a"].InternalIP.IP},
						wireGuardIP: w1,
					},
					{
						AllowedIPs:  allowedIPs(nodes["b"].Subnet.String(), "192.168.0.1/32", "10.4.0.2/32"),
						Endpoint:    nodes["b"].ExternalIP.IP.String(),
						Key:         string(nodes["b"].Key),
						Location:    nodes["b"].Name,
						cidrs:       []*net.IPNet{nodes["b"].Subnet},
						hostnames:   []string{"b"},
						privateIPs:  []net.IP{nodes["b"].InternalIP.IP},
						wireGuardIP: w2,
					},
					{
						AllowedIPs:  allowedIPs(nodes["c"].Subnet.String(), "192.168.0.2/32", "10.4.0.3/32"),
						Endpoint:    nodes["c"].ExternalIP.IP.String(),
						Key:         string(nodes["c"].Key),
						Location:    nodes["c"].Name,
						cidrs:       []*net.IPNet{nodes["c"].Subnet},
						hostnames:   []string{"c"},
						privateIPs:  []net.IP{nodes["c"].InternalIP.IP},
						wireGuardIP: w3,
					},
				},
			},
		},
	} {
		tc.result.Key = string(key)
		tc.result.Port = port
		topo, err := NewTopology(nodes, tc.granularity, tc.hostname, port, key, kiloNet)
		if err != nil {
			t.Errorf("test case %q: failed to generate Topology: %v", tc.name, err)
		}
		if diff := pretty.Compare(topo, tc.result); diff != "" {
			t.Errorf("test case %q: got diff: %v", tc.name, diff)
		}
	}
}

func mustTopo(t *testing.T, nodes map[string]*Node, granularity Granularity, hostname string, port int, key []byte, subnet *net.IPNet) *Topology {
	topo, err := NewTopology(nodes, granularity, hostname, port, key, subnet)
	if err != nil {
		t.Errorf("failed to generate Topology: %v", err)
	}
	return topo
}

func TestRoutes(t *testing.T) {
	nodes, key, port, kiloNet := setup(t)
	kiloIface := 0
	privIface := 1
	pubIface := 2
	mustTopoForGranularityAndHost := func(granularity Granularity, hostname string) *Topology {
		return mustTopo(t, nodes, granularity, hostname, port, key, kiloNet)
	}

	for _, tc := range []struct {
		name     string
		local    bool
		topology *Topology
		result   []*netlink.Route
	}{
		{
			name:     "datacenter from a",
			topology: mustTopoForGranularityAndHost(DataCenterGranularity, nodes["a"].Name),
			result: []*netlink.Route{
				{
					Dst:       mustTopoForGranularityAndHost(DataCenterGranularity, nodes["a"].Name).Segments[1].cidrs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(DataCenterGranularity, nodes["a"].Name).Segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["b"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(DataCenterGranularity, nodes["a"].Name).Segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       mustTopoForGranularityAndHost(DataCenterGranularity, nodes["a"].Name).Segments[1].cidrs[1],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(DataCenterGranularity, nodes["a"].Name).Segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["c"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(DataCenterGranularity, nodes["a"].Name).Segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
			},
		},
		{
			name:     "datacenter from b",
			topology: mustTopoForGranularityAndHost(DataCenterGranularity, nodes["b"].Name),
			result: []*netlink.Route{
				{
					Dst:       mustTopoForGranularityAndHost(DataCenterGranularity, nodes["b"].Name).Segments[0].cidrs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(DataCenterGranularity, nodes["b"].Name).Segments[0].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["a"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(DataCenterGranularity, nodes["b"].Name).Segments[0].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
			},
		},
		{
			name:     "datacenter from c",
			topology: mustTopoForGranularityAndHost(DataCenterGranularity, nodes["c"].Name),
			result: []*netlink.Route{
				{
					Dst:       oneAddressCIDR(mustTopoForGranularityAndHost(DataCenterGranularity, nodes["c"].Name).Segments[0].wireGuardIP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["b"].InternalIP.IP,
					LinkIndex: privIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       mustTopoForGranularityAndHost(DataCenterGranularity, nodes["c"].Name).Segments[0].cidrs[0],
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
					Dst:       oneAddressCIDR(mustTopoForGranularityAndHost(DataCenterGranularity, nodes["c"].Name).Segments[1].wireGuardIP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["b"].InternalIP.IP,
					LinkIndex: privIface,
					Protocol:  unix.RTPROT_STATIC,
				},
			},
		},
		{
			name:     "node from a",
			topology: mustTopoForGranularityAndHost(NodeGranularity, nodes["a"].Name),
			result: []*netlink.Route{
				{
					Dst:       mustTopoForGranularityAndHost(NodeGranularity, nodes["a"].Name).Segments[1].cidrs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(NodeGranularity, nodes["a"].Name).Segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["b"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(NodeGranularity, nodes["a"].Name).Segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       mustTopoForGranularityAndHost(NodeGranularity, nodes["a"].Name).Segments[2].cidrs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(NodeGranularity, nodes["a"].Name).Segments[2].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["c"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(NodeGranularity, nodes["a"].Name).Segments[2].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
			},
		},
		{
			name:     "node from b",
			topology: mustTopoForGranularityAndHost(NodeGranularity, nodes["b"].Name),
			result: []*netlink.Route{
				{
					Dst:       mustTopoForGranularityAndHost(NodeGranularity, nodes["b"].Name).Segments[0].cidrs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(NodeGranularity, nodes["b"].Name).Segments[0].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["a"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(NodeGranularity, nodes["b"].Name).Segments[0].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       mustTopoForGranularityAndHost(NodeGranularity, nodes["b"].Name).Segments[2].cidrs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(NodeGranularity, nodes["b"].Name).Segments[2].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["c"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(NodeGranularity, nodes["b"].Name).Segments[2].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
			},
		},
		{
			name:     "node from c",
			topology: mustTopoForGranularityAndHost(NodeGranularity, nodes["c"].Name),
			result: []*netlink.Route{
				{
					Dst:       mustTopoForGranularityAndHost(NodeGranularity, nodes["c"].Name).Segments[0].cidrs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(NodeGranularity, nodes["c"].Name).Segments[0].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["a"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(NodeGranularity, nodes["c"].Name).Segments[0].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       mustTopoForGranularityAndHost(NodeGranularity, nodes["c"].Name).Segments[1].cidrs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(NodeGranularity, nodes["c"].Name).Segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["b"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(NodeGranularity, nodes["c"].Name).Segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
			},
		},
		{
			name:     "datacenter from a local",
			local:    true,
			topology: mustTopoForGranularityAndHost(DataCenterGranularity, nodes["a"].Name),
			result: []*netlink.Route{
				{
					Dst:       nodes["b"].Subnet,
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(DataCenterGranularity, nodes["a"].Name).Segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["b"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(DataCenterGranularity, nodes["a"].Name).Segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       nodes["c"].Subnet,
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(DataCenterGranularity, nodes["a"].Name).Segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["c"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(DataCenterGranularity, nodes["a"].Name).Segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
			},
		},
		{
			name:     "datacenter from b local",
			local:    true,
			topology: mustTopoForGranularityAndHost(DataCenterGranularity, nodes["b"].Name),
			result: []*netlink.Route{
				{
					Dst:       nodes["a"].Subnet,
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(DataCenterGranularity, nodes["b"].Name).Segments[0].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["a"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(DataCenterGranularity, nodes["b"].Name).Segments[0].wireGuardIP,
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
			},
		},
		{
			name:     "datacenter from c local",
			local:    true,
			topology: mustTopoForGranularityAndHost(DataCenterGranularity, nodes["c"].Name),
			result: []*netlink.Route{
				{
					Dst:       oneAddressCIDR(mustTopoForGranularityAndHost(DataCenterGranularity, nodes["c"].Name).Segments[0].wireGuardIP),
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
					Dst:       oneAddressCIDR(mustTopoForGranularityAndHost(DataCenterGranularity, nodes["c"].Name).Segments[1].wireGuardIP),
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
			},
		},
		{
			name:     "node from a local",
			local:    true,
			topology: mustTopoForGranularityAndHost(NodeGranularity, nodes["a"].Name),
			result: []*netlink.Route{
				{
					Dst:       nodes["b"].Subnet,
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(NodeGranularity, nodes["a"].Name).Segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["b"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(NodeGranularity, nodes["a"].Name).Segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       nodes["c"].Subnet,
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(NodeGranularity, nodes["a"].Name).Segments[2].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["c"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(NodeGranularity, nodes["a"].Name).Segments[2].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
			},
		},
		{
			name:     "node from b local",
			local:    true,
			topology: mustTopoForGranularityAndHost(NodeGranularity, nodes["b"].Name),
			result: []*netlink.Route{
				{
					Dst:       nodes["a"].Subnet,
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(NodeGranularity, nodes["b"].Name).Segments[0].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["a"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(NodeGranularity, nodes["b"].Name).Segments[0].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       nodes["c"].Subnet,
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(NodeGranularity, nodes["b"].Name).Segments[2].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["c"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(NodeGranularity, nodes["b"].Name).Segments[2].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
			},
		},
		{
			name:     "node from c local",
			local:    true,
			topology: mustTopoForGranularityAndHost(NodeGranularity, nodes["c"].Name),
			result: []*netlink.Route{
				{
					Dst:       nodes["a"].Subnet,
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(NodeGranularity, nodes["c"].Name).Segments[0].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["a"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(NodeGranularity, nodes["c"].Name).Segments[0].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       nodes["b"].Subnet,
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(NodeGranularity, nodes["c"].Name).Segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["b"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(NodeGranularity, nodes["c"].Name).Segments[1].wireGuardIP,
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
	nodes, key, port, kiloNet := setup(t)
	for _, tc := range []struct {
		name     string
		topology *Topology
		result   string
	}{
		{
			name:     "datacenter from a",
			topology: mustTopo(t, nodes, DataCenterGranularity, nodes["a"].Name, port, key, kiloNet),
			result: `[Interface]
PrivateKey = private
ListenPort = 51820

[Peer]
PublicKey = key2
Endpoint = 10.1.0.2:51820
AllowedIPs = 10.2.2.0/24, 192.168.0.1/32, 10.2.3.0/24, 192.168.0.2/32, 10.4.0.2/32
`,
		},
		{
			name:     "datacenter from b",
			topology: mustTopo(t, nodes, DataCenterGranularity, nodes["b"].Name, port, key, kiloNet),
			result: `[Interface]
PrivateKey = private
ListenPort = 51820

[Peer]
PublicKey = key1
Endpoint = 10.1.0.1:51820
AllowedIPs = 10.2.1.0/24, 192.168.0.1/32, 10.4.0.1/32
`,
		},
		{
			name:     "datacenter from c",
			topology: mustTopo(t, nodes, DataCenterGranularity, nodes["c"].Name, port, key, kiloNet),
			result: `[Interface]
PrivateKey = private
ListenPort = 51820

[Peer]
PublicKey = key1
Endpoint = 10.1.0.1:51820
AllowedIPs = 10.2.1.0/24, 192.168.0.1/32, 10.4.0.1/32
`,
		},
		{
			name:     "node from a",
			topology: mustTopo(t, nodes, NodeGranularity, nodes["a"].Name, port, key, kiloNet),
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
`,
		},
		{
			name:     "node from b",
			topology: mustTopo(t, nodes, NodeGranularity, nodes["b"].Name, port, key, kiloNet),
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
`,
		},
		{
			name:     "node from c",
			topology: mustTopo(t, nodes, NodeGranularity, nodes["c"].Name, port, key, kiloNet),
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
`,
		},
	} {
		conf, err := tc.topology.Conf()
		if err != nil {
			t.Errorf("test case %q: failed to generate conf: %v", tc.name, err)
		}
		if string(conf) != tc.result {
			t.Errorf("test case %q: expected %s got %s", tc.name, tc.result, string(conf))
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
