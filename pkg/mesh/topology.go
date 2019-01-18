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
	"bytes"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"text/template"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var (
	confTemplate = template.Must(template.New("").Parse(`[Interface]
PrivateKey = {{.Key}}
ListenPort = {{.Port}}
{{range .Segments -}}
{{if ne .Location $.Location}}
[Peer]
PublicKey = {{.Key}}
Endpoint = {{.Endpoint}}:{{$.Port}}
AllowedIPs = {{.AllowedIPs}}
{{end}}
{{- end -}}
`))
)

// Topology represents the logical structure of the overlay network.
type Topology struct {
	// Some fields need to be exported so that the template can read them.
	Key  string
	Port int
	// Location is the logical location of the local host.
	Location string
	Segments []*segment

	// hostname is the hostname of the local host.
	hostname string
	// leader represents whether or not the local host
	// is the segment leader.
	leader bool
	// subnet is the entire subnet from which IPs
	// for the WireGuard interfaces will be allocated.
	subnet *net.IPNet
	// privateIP is the private IP address  of the local node.
	privateIP *net.IPNet
	// wireGuardCIDR is the allocated CIDR of the WireGuard
	// interface of the local node. If the local node is not
	// the leader, then it is nil.
	wireGuardCIDR *net.IPNet
}

type segment struct {
	// Some fields need to be exported so that the template can read them.
	AllowedIPs string
	Endpoint   string
	Key        string
	// Location is the logical location of this segment.
	Location string

	// cidrs is a slice of subnets of all peers in the segment.
	cidrs []*net.IPNet
	// hostnames is a slice of the hostnames of the peers in the segment.
	hostnames []string
	// leader is the index of the leader of the segment.
	leader int
	// privateIPs is a slice of private IPs of all peers in the segment.
	privateIPs []net.IP
	// wireGuardIP is the allocated IP address of the WireGuard
	// interface on the leader of the segment.
	wireGuardIP net.IP
}

// NewTopology creates a new Topology struct from a given set of nodes.
func NewTopology(nodes map[string]*Node, granularity Granularity, hostname string, port int, key []byte, subnet *net.IPNet) (*Topology, error) {
	topoMap := make(map[string][]*Node)
	for _, node := range nodes {
		var location string
		switch granularity {
		case DataCenterGranularity:
			location = node.Location
		case NodeGranularity:
			location = node.Name
		}
		topoMap[location] = append(topoMap[location], node)
	}
	var localLocation string
	switch granularity {
	case DataCenterGranularity:
		localLocation = nodes[hostname].Location
	case NodeGranularity:
		localLocation = hostname
	}

	t := Topology{Key: strings.TrimSpace(string(key)), Port: port, hostname: hostname, Location: localLocation, subnet: subnet, privateIP: nodes[hostname].InternalIP}
	for location := range topoMap {
		// Sort the location so the result is stable.
		sort.Slice(topoMap[location], func(i, j int) bool {
			return topoMap[location][i].Name < topoMap[location][j].Name
		})
		leader := findLeader(topoMap[location])
		if location == localLocation && topoMap[location][leader].Name == hostname {
			t.leader = true
		}
		var allowedIPs []string
		var cidrs []*net.IPNet
		var hostnames []string
		var privateIPs []net.IP
		for _, node := range topoMap[location] {
			// Allowed IPs should include:
			// - the node's allocated subnet
			// - the node's WireGuard IP
			// - the node's internal IP
			allowedIPs = append(allowedIPs, node.Subnet.String(), oneAddressCIDR(node.InternalIP.IP).String())
			cidrs = append(cidrs, node.Subnet)
			hostnames = append(hostnames, node.Name)
			privateIPs = append(privateIPs, node.InternalIP.IP)
		}
		t.Segments = append(t.Segments, &segment{
			AllowedIPs: strings.Join(allowedIPs, ", "),
			Endpoint:   topoMap[location][leader].ExternalIP.IP.String(),
			Key:        strings.TrimSpace(string(topoMap[location][leader].Key)),
			Location:   location,
			cidrs:      cidrs,
			hostnames:  hostnames,
			leader:     leader,
			privateIPs: privateIPs,
		})
	}
	// Sort the Topology so the result is stable.
	sort.Slice(t.Segments, func(i, j int) bool {
		return t.Segments[i].Location < t.Segments[j].Location
	})

	// Allocate IPs to the segment leaders in a stable, coordination-free manner.
	a := newAllocator(*subnet)
	for _, segment := range t.Segments {
		ipNet := a.next()
		if ipNet == nil {
			return nil, errors.New("failed to allocate an IP address; ran out of IP addresses")
		}
		segment.wireGuardIP = ipNet.IP
		segment.AllowedIPs = fmt.Sprintf("%s, %s", segment.AllowedIPs, ipNet.String())
		if t.leader && segment.Location == t.Location {
			t.wireGuardCIDR = &net.IPNet{IP: ipNet.IP, Mask: t.subnet.Mask}
		}
	}

	return &t, nil
}

// RemoteSubnets identifies the subnets of the hosts in segments different than the host's.
func (t *Topology) RemoteSubnets() []*net.IPNet {
	var remote []*net.IPNet
	for _, s := range t.Segments {
		if s == nil || s.Location == t.Location {
			continue
		}
		remote = append(remote, s.cidrs...)
	}
	return remote
}

// Routes generates a slice of routes for a given Topology.
func (t *Topology) Routes(kiloIface, privIface, tunlIface int, local bool, encapsulate Encapsulate) []*netlink.Route {
	var routes []*netlink.Route
	if !t.leader {
		// Find the leader for this segment.
		var leader net.IP
		for _, segment := range t.Segments {
			if segment.Location == t.Location {
				leader = segment.privateIPs[segment.leader]
				break
			}
		}
		for _, segment := range t.Segments {
			// First, add a route to the WireGuard IP of the segment.
			routes = append(routes, encapsulateRoute(&netlink.Route{
				Dst:       oneAddressCIDR(segment.wireGuardIP),
				Flags:     int(netlink.FLAG_ONLINK),
				Gw:        leader,
				LinkIndex: privIface,
				Protocol:  unix.RTPROT_STATIC,
			}, encapsulate, t.privateIP, tunlIface))
			// Add routes for the current segment if local is true.
			if segment.Location == t.Location {
				if local {
					for i := range segment.cidrs {
						// Don't add routes for the local node.
						if segment.privateIPs[i].Equal(t.privateIP.IP) {
							continue
						}
						routes = append(routes, encapsulateRoute(&netlink.Route{
							Dst:       segment.cidrs[i],
							Flags:     int(netlink.FLAG_ONLINK),
							Gw:        segment.privateIPs[i],
							LinkIndex: privIface,
							Protocol:  unix.RTPROT_STATIC,
						}, encapsulate, t.privateIP, tunlIface))
					}
				}
				continue
			}
			for i := range segment.cidrs {
				// Add routes to the Pod CIDRs of nodes in other segments.
				routes = append(routes, encapsulateRoute(&netlink.Route{
					Dst:       segment.cidrs[i],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        leader,
					LinkIndex: privIface,
					Protocol:  unix.RTPROT_STATIC,
				}, encapsulate, t.privateIP, tunlIface))
				// Add routes to the private IPs of nodes in other segments.
				// Number of CIDRs and private IPs always match so
				// we can reuse the loop.
				routes = append(routes, encapsulateRoute(&netlink.Route{
					Dst:       oneAddressCIDR(segment.privateIPs[i]),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        leader,
					LinkIndex: privIface,
					Protocol:  unix.RTPROT_STATIC,
				}, encapsulate, t.privateIP, tunlIface))
			}
		}
		return routes
	}
	for _, segment := range t.Segments {
		// Add routes for the current segment if local is true.
		if segment.Location == t.Location {
			if local {
				for i := range segment.cidrs {
					// Don't add routes for the local node.
					if segment.privateIPs[i].Equal(t.privateIP.IP) {
						continue
					}
					routes = append(routes, encapsulateRoute(&netlink.Route{
						Dst:       segment.cidrs[i],
						Flags:     int(netlink.FLAG_ONLINK),
						Gw:        segment.privateIPs[i],
						LinkIndex: privIface,
						Protocol:  unix.RTPROT_STATIC,
					}, encapsulate, t.privateIP, tunlIface))
				}
			}
			continue
		}
		for i := range segment.cidrs {
			// Add routes to the Pod CIDRs of nodes in other segments.
			routes = append(routes, &netlink.Route{
				Dst:       segment.cidrs[i],
				Flags:     int(netlink.FLAG_ONLINK),
				Gw:        segment.wireGuardIP,
				LinkIndex: kiloIface,
				Protocol:  unix.RTPROT_STATIC,
			})
			// Add routes to the private IPs of nodes in other segments.
			// Number of CIDRs and private IPs always match so
			// we can reuse the loop.
			routes = append(routes, &netlink.Route{
				Dst:       oneAddressCIDR(segment.privateIPs[i]),
				Flags:     int(netlink.FLAG_ONLINK),
				Gw:        segment.wireGuardIP,
				LinkIndex: kiloIface,
				Protocol:  unix.RTPROT_STATIC,
			})
		}
	}
	return routes
}

func encapsulateRoute(route *netlink.Route, encapsulate Encapsulate, subnet *net.IPNet, tunlIface int) *netlink.Route {
	if encapsulate == AlwaysEncapsulate || (encapsulate == CrossSubnetEncapsulate && !subnet.Contains(route.Gw)) {
		route.LinkIndex = tunlIface
	}
	return route
}

// Conf generates a WireGuard configuration file for a given Topology.
func (t *Topology) Conf() ([]byte, error) {
	conf := new(bytes.Buffer)
	if err := confTemplate.Execute(conf, t); err != nil {
		return nil, err
	}
	return conf.Bytes(), nil
}

// oneAddressCIDR takes an IP address and returns a CIDR
// that contains only that address.
func oneAddressCIDR(ip net.IP) *net.IPNet {
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(len(ip)*8, len(ip)*8)}
}

// findLeader selects a leader for the nodes in a segment;
// it will select the first node that says it should lead
// or the first node in the segment if none have volunteered,
// always preferring those with a public external IP address,
func findLeader(nodes []*Node) int {
	var leaders, public []int
	for i := range nodes {
		if nodes[i].Leader {
			if isPublic(nodes[i].ExternalIP) {
				return i
			}
			leaders = append(leaders, i)
		}
		if isPublic(nodes[i].ExternalIP) {
			public = append(public, i)
		}
	}
	if len(leaders) != 0 {
		return leaders[0]
	}
	if len(public) != 0 {
		return public[0]
	}
	return 0
}
