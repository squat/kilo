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
	"testing"

	"github.com/kylelemons/godebug/pretty"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/squat/kilo/pkg/encapsulation"
)

func TestRoutes(t *testing.T) {
	nodes, peers, key, port := setup(t)
	kiloIface := 0
	privIface := 1
	tunlIface := 2
	mustTopoForGranularityAndHost := func(granularity Granularity, hostname string) *Topology {
		return mustTopo(t, nodes, peers, granularity, hostname, port, key, DefaultKiloSubnet, 0)
	}

	for _, tc := range []struct {
		name     string
		local    bool
		topology *Topology
		strategy encapsulation.Strategy
		routes   []*netlink.Route
		rules    []*netlink.Rule
	}{
		{
			name:     "logical from a",
			topology: mustTopoForGranularityAndHost(LogicalGranularity, nodes["a"].Name),
			strategy: encapsulation.Never,
			routes: []*netlink.Route{
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
					Dst:       &nodes["b"].AllowedLocationIPs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(LogicalGranularity, nodes["a"].Name).segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       mustTopoForGranularityAndHost(LogicalGranularity, nodes["a"].Name).segments[2].cidrs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(LogicalGranularity, nodes["a"].Name).segments[2].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["a"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["a"].AllowedIPs[1],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["b"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
			},
		},
		{
			name:     "logical from b",
			topology: mustTopoForGranularityAndHost(LogicalGranularity, nodes["b"].Name),
			strategy: encapsulation.Never,
			routes: []*netlink.Route{
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
					Dst:       mustTopoForGranularityAndHost(LogicalGranularity, nodes["b"].Name).segments[2].cidrs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(LogicalGranularity, nodes["b"].Name).segments[2].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["a"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["a"].AllowedIPs[1],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["b"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
			},
		},
		{
			name:     "logical from c",
			topology: mustTopoForGranularityAndHost(LogicalGranularity, nodes["c"].Name),
			strategy: encapsulation.Never,
			routes: []*netlink.Route{
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
					Dst:       oneAddressCIDR(mustTopoForGranularityAndHost(LogicalGranularity, nodes["c"].Name).segments[2].wireGuardIP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["b"].InternalIP.IP,
					LinkIndex: privIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       mustTopoForGranularityAndHost(LogicalGranularity, nodes["c"].Name).segments[2].cidrs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["b"].InternalIP.IP,
					LinkIndex: privIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["a"].AllowedIPs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["b"].InternalIP.IP,
					LinkIndex: privIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["a"].AllowedIPs[1],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["b"].InternalIP.IP,
					LinkIndex: privIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["b"].AllowedIPs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["b"].InternalIP.IP,
					LinkIndex: privIface,
					Protocol:  unix.RTPROT_STATIC,
				},
			},
		},
		{
			name:     "logical from d",
			topology: mustTopoForGranularityAndHost(LogicalGranularity, nodes["d"].Name),
			strategy: encapsulation.Never,
			routes: []*netlink.Route{
				{
					Dst:       mustTopoForGranularityAndHost(LogicalGranularity, nodes["d"].Name).segments[0].cidrs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(LogicalGranularity, nodes["d"].Name).segments[0].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["a"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(LogicalGranularity, nodes["d"].Name).segments[0].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       mustTopoForGranularityAndHost(LogicalGranularity, nodes["d"].Name).segments[1].cidrs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(LogicalGranularity, nodes["d"].Name).segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["b"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(LogicalGranularity, nodes["d"].Name).segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       mustTopoForGranularityAndHost(LogicalGranularity, nodes["d"].Name).segments[1].cidrs[1],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(LogicalGranularity, nodes["d"].Name).segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["c"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(LogicalGranularity, nodes["d"].Name).segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &nodes["b"].AllowedLocationIPs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(LogicalGranularity, nodes["d"].Name).segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["a"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["a"].AllowedIPs[1],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["b"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
			},
		},
		{
			name:     "full from a",
			topology: mustTopoForGranularityAndHost(FullGranularity, nodes["a"].Name),
			strategy: encapsulation.Never,
			routes: []*netlink.Route{
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
					Dst:       &nodes["b"].AllowedLocationIPs[0],
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
					Dst:       mustTopoForGranularityAndHost(FullGranularity, nodes["a"].Name).segments[3].cidrs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(FullGranularity, nodes["a"].Name).segments[3].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["a"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["a"].AllowedIPs[1],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["b"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
			},
		},
		{
			name:     "full from b",
			topology: mustTopoForGranularityAndHost(FullGranularity, nodes["b"].Name),
			strategy: encapsulation.Never,
			routes: []*netlink.Route{
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
					Dst:       mustTopoForGranularityAndHost(FullGranularity, nodes["b"].Name).segments[3].cidrs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(FullGranularity, nodes["b"].Name).segments[3].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["a"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["a"].AllowedIPs[1],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["b"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
			},
		},
		{
			name:     "full from c",
			topology: mustTopoForGranularityAndHost(FullGranularity, nodes["c"].Name),
			strategy: encapsulation.Never,
			routes: []*netlink.Route{
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
					Dst:       &nodes["b"].AllowedLocationIPs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(FullGranularity, nodes["c"].Name).segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       mustTopoForGranularityAndHost(FullGranularity, nodes["c"].Name).segments[3].cidrs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(FullGranularity, nodes["c"].Name).segments[3].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["a"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["a"].AllowedIPs[1],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["b"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
			},
		},
		{
			name:     "logical from a local",
			local:    true,
			topology: mustTopoForGranularityAndHost(LogicalGranularity, nodes["a"].Name),
			strategy: encapsulation.Never,
			routes: []*netlink.Route{
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
					Dst:       &nodes["b"].AllowedLocationIPs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(LogicalGranularity, nodes["a"].Name).segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       nodes["d"].Subnet,
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(LogicalGranularity, nodes["a"].Name).segments[2].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["a"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["a"].AllowedIPs[1],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["b"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
			},
		},
		{
			name:     "logical from a local always",
			local:    true,
			topology: mustTopoForGranularityAndHost(LogicalGranularity, nodes["a"].Name),
			strategy: encapsulation.Always,
			routes: []*netlink.Route{
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
					Dst:       &nodes["b"].AllowedLocationIPs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(LogicalGranularity, nodes["a"].Name).segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       nodes["d"].Subnet,
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(LogicalGranularity, nodes["a"].Name).segments[2].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["a"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["a"].AllowedIPs[1],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["b"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
			},
		},
		{
			name:     "logical from b local",
			local:    true,
			topology: mustTopoForGranularityAndHost(LogicalGranularity, nodes["b"].Name),
			strategy: encapsulation.Never,
			routes: []*netlink.Route{
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
					Dst:       nodes["d"].Subnet,
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(LogicalGranularity, nodes["b"].Name).segments[2].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["a"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["a"].AllowedIPs[1],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["b"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
			},
		},
		{
			name:     "logical from b local always",
			local:    true,
			topology: mustTopoForGranularityAndHost(LogicalGranularity, nodes["b"].Name),
			strategy: encapsulation.Always,
			routes: []*netlink.Route{
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
					LinkIndex: tunlIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["c"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["c"].InternalIP.IP,
					LinkIndex: tunlIface,
					Protocol:  unix.RTPROT_STATIC,
					Table:     kiloTableIndex,
				},
				{
					Dst:       nodes["d"].Subnet,
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(LogicalGranularity, nodes["b"].Name).segments[2].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["a"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["a"].AllowedIPs[1],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["b"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
			},
			rules: []*netlink.Rule{
				defaultRule(&netlink.Rule{
					Src:   nodes["b"].Subnet,
					Dst:   nodes["c"].InternalIP,
					Table: kiloTableIndex,
				}),
				defaultRule(&netlink.Rule{
					Dst:     nodes["c"].InternalIP,
					IifName: DefaultKiloInterface,
					Table:   kiloTableIndex,
				}),
			},
		},
		{
			name:     "logical from c local",
			local:    true,
			topology: mustTopoForGranularityAndHost(LogicalGranularity, nodes["c"].Name),
			strategy: encapsulation.Never,
			routes: []*netlink.Route{
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
					Dst:       oneAddressCIDR(mustTopoForGranularityAndHost(LogicalGranularity, nodes["c"].Name).segments[2].wireGuardIP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["b"].InternalIP.IP,
					LinkIndex: privIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       nodes["d"].Subnet,
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["b"].InternalIP.IP,
					LinkIndex: privIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["a"].AllowedIPs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["b"].InternalIP.IP,
					LinkIndex: privIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["a"].AllowedIPs[1],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["b"].InternalIP.IP,
					LinkIndex: privIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["b"].AllowedIPs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["b"].InternalIP.IP,
					LinkIndex: privIface,
					Protocol:  unix.RTPROT_STATIC,
				},
			},
		},
		{
			name:     "logical from c local always",
			local:    true,
			topology: mustTopoForGranularityAndHost(LogicalGranularity, nodes["c"].Name),
			strategy: encapsulation.Always,
			routes: []*netlink.Route{
				{
					Dst:       oneAddressCIDR(mustTopoForGranularityAndHost(LogicalGranularity, nodes["c"].Name).segments[0].wireGuardIP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["b"].InternalIP.IP,
					LinkIndex: tunlIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       nodes["a"].Subnet,
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["b"].InternalIP.IP,
					LinkIndex: tunlIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(nodes["a"].InternalIP.IP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["b"].InternalIP.IP,
					LinkIndex: tunlIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       oneAddressCIDR(mustTopoForGranularityAndHost(LogicalGranularity, nodes["c"].Name).segments[1].wireGuardIP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["b"].InternalIP.IP,
					LinkIndex: tunlIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       nodes["b"].Subnet,
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["b"].InternalIP.IP,
					LinkIndex: tunlIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       nodes["b"].InternalIP,
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["b"].InternalIP.IP,
					LinkIndex: tunlIface,
					Protocol:  unix.RTPROT_STATIC,
					Table:     kiloTableIndex,
				},
				{
					Dst:       oneAddressCIDR(mustTopoForGranularityAndHost(LogicalGranularity, nodes["c"].Name).segments[2].wireGuardIP),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["b"].InternalIP.IP,
					LinkIndex: tunlIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       nodes["d"].Subnet,
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["b"].InternalIP.IP,
					LinkIndex: tunlIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["a"].AllowedIPs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["b"].InternalIP.IP,
					LinkIndex: tunlIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["a"].AllowedIPs[1],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["b"].InternalIP.IP,
					LinkIndex: tunlIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["b"].AllowedIPs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        nodes["b"].InternalIP.IP,
					LinkIndex: tunlIface,
					Protocol:  unix.RTPROT_STATIC,
				},
			},
			rules: []*netlink.Rule{
				defaultRule(&netlink.Rule{
					Src:   nodes["c"].Subnet,
					Dst:   nodes["b"].InternalIP,
					Table: kiloTableIndex,
				}),
			},
		},
		{
			name:     "full from a local",
			local:    true,
			topology: mustTopoForGranularityAndHost(FullGranularity, nodes["a"].Name),
			strategy: encapsulation.Never,
			routes: []*netlink.Route{
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
					Dst:       &nodes["b"].AllowedLocationIPs[0],
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
					Dst:       nodes["d"].Subnet,
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(FullGranularity, nodes["a"].Name).segments[3].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["a"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["a"].AllowedIPs[1],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["b"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
			},
		},
		{
			name:     "full from b local",
			local:    true,
			topology: mustTopoForGranularityAndHost(FullGranularity, nodes["b"].Name),
			strategy: encapsulation.Never,
			routes: []*netlink.Route{
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
					Dst:       nodes["d"].Subnet,
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(FullGranularity, nodes["b"].Name).segments[3].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["a"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["a"].AllowedIPs[1],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["b"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
			},
		},
		{
			name:     "full from c local",
			local:    true,
			topology: mustTopoForGranularityAndHost(FullGranularity, nodes["c"].Name),
			strategy: encapsulation.Never,
			routes: []*netlink.Route{
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
					Dst:       &nodes["b"].AllowedLocationIPs[0],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(FullGranularity, nodes["c"].Name).segments[1].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       nodes["d"].Subnet,
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        mustTopoForGranularityAndHost(FullGranularity, nodes["c"].Name).segments[3].wireGuardIP,
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["a"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["a"].AllowedIPs[1],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
				{
					Dst:       &peers["b"].AllowedIPs[0],
					LinkIndex: kiloIface,
					Protocol:  unix.RTPROT_STATIC,
				},
			},
		},
	} {
		routes, rules := tc.topology.Routes(DefaultKiloInterface, kiloIface, privIface, tunlIface, tc.local, encapsulation.NewIPIP(tc.strategy, true))
		if diff := pretty.Compare(routes, tc.routes); diff != "" {
			t.Errorf("test case %q: got diff: %v", tc.name, diff)
		}
		if diff := pretty.Compare(rules, tc.rules); diff != "" {
			t.Errorf("test case %q: got diff: %v", tc.name, diff)
		}
	}
}
