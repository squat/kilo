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
	"errors"
	"net"
	"sort"

	"github.com/squat/kilo/pkg/encapsulation"
	"github.com/squat/kilo/pkg/wireguard"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Topology represents the logical structure of the overlay network.
type Topology struct {
	// key is the private key of the node creating the topology.
	key  []byte
	port uint32
	// Location is the logical location of the local host.
	location string
	segments []*segment
	peers    []*Peer

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
	allowedIPs []*net.IPNet
	endpoint   net.IP
	key        []byte
	// Location is the logical location of this segment.
	location string

	// cidrs is a slice of subnets of all peers in the segment.
	cidrs []*net.IPNet
	// hostnames is a slice of the hostnames of the peers in the segment.
	hostnames []string
	// leader is the index of the leader of the segment.
	leader int
	// persistentKeepalive is the interval in seconds of the emission
	// of keepalive packets to the peer.
	persistentKeepalive int
	// privateIPs is a slice of private IPs of all peers in the segment.
	privateIPs []net.IP
	// wireGuardIP is the allocated IP address of the WireGuard
	// interface on the leader of the segment.
	wireGuardIP net.IP
}

// NewTopology creates a new Topology struct from a given set of nodes and peers.
func NewTopology(nodes map[string]*Node, peers map[string]*Peer, granularity Granularity, hostname string, port uint32, key []byte, subnet *net.IPNet) (*Topology, error) {
	topoMap := make(map[string][]*Node)
	for _, node := range nodes {
		var location string
		switch granularity {
		case LogicalGranularity:
			location = node.Location
		case FullGranularity:
			location = node.Name
		}
		topoMap[location] = append(topoMap[location], node)
	}
	var localLocation string
	switch granularity {
	case LogicalGranularity:
		localLocation = nodes[hostname].Location
	case FullGranularity:
		localLocation = hostname
	}

	t := Topology{key: key, port: port, hostname: hostname, location: localLocation, subnet: subnet, privateIP: nodes[hostname].InternalIP}
	for location := range topoMap {
		// Sort the location so the result is stable.
		sort.Slice(topoMap[location], func(i, j int) bool {
			return topoMap[location][i].Name < topoMap[location][j].Name
		})
		leader := findLeader(topoMap[location])
		if location == localLocation && topoMap[location][leader].Name == hostname {
			t.leader = true
		}
		var allowedIPs []*net.IPNet
		var cidrs []*net.IPNet
		var hostnames []string
		var privateIPs []net.IP
		for _, node := range topoMap[location] {
			// Allowed IPs should include:
			// - the node's allocated subnet
			// - the node's WireGuard IP
			// - the node's internal IP
			allowedIPs = append(allowedIPs, node.Subnet, oneAddressCIDR(node.InternalIP.IP))
			cidrs = append(cidrs, node.Subnet)
			hostnames = append(hostnames, node.Name)
			privateIPs = append(privateIPs, node.InternalIP.IP)
		}
		t.segments = append(t.segments, &segment{
			allowedIPs:          allowedIPs,
			endpoint:            topoMap[location][leader].ExternalIP.IP,
			key:                 topoMap[location][leader].Key,
			location:            location,
			cidrs:               cidrs,
			hostnames:           hostnames,
			leader:              leader,
			privateIPs:          privateIPs,
			persistentKeepalive: topoMap[location][leader].PersistentKeepalive,
		})
	}
	// Sort the Topology segments so the result is stable.
	sort.Slice(t.segments, func(i, j int) bool {
		return t.segments[i].location < t.segments[j].location
	})

	for _, peer := range peers {
		t.peers = append(t.peers, peer)
	}
	// Sort the Topology peers so the result is stable.
	sort.Slice(t.peers, func(i, j int) bool {
		return t.peers[i].Name < t.peers[j].Name
	})
	// We need to defensively deduplicate peer allowed IPs. If two peers claim the same IP,
	// the WireGuard configuration could flap, causing the interface to churn.
	t.peers = deduplicatePeerIPs(t.peers)
	// Allocate IPs to the segment leaders in a stable, coordination-free manner.
	a := newAllocator(*subnet)
	for _, segment := range t.segments {
		ipNet := a.next()
		if ipNet == nil {
			return nil, errors.New("failed to allocate an IP address; ran out of IP addresses")
		}
		segment.wireGuardIP = ipNet.IP
		segment.allowedIPs = append(segment.allowedIPs, oneAddressCIDR(ipNet.IP))
		if t.leader && segment.location == t.location {
			t.wireGuardCIDR = &net.IPNet{IP: ipNet.IP, Mask: t.subnet.Mask}
		}
	}

	return &t, nil
}

// Routes generates a slice of routes for a given Topology.
func (t *Topology) Routes(kiloIface, privIface, tunlIface int, local bool, enc encapsulation.Encapsulator) []*netlink.Route {
	var routes []*netlink.Route
	if !t.leader {
		// Find the GW for this segment.
		// This will be the an IP of the leader.
		// In an IPIP encapsulated mesh it is the leader's private IP.
		var gw net.IP
		for _, segment := range t.segments {
			if segment.location == t.location {
				gw = enc.Gw(segment.endpoint, segment.privateIPs[segment.leader], segment.cidrs[segment.leader])
				break
			}
		}
		for _, segment := range t.segments {
			// First, add a route to the WireGuard IP of the segment.
			routes = append(routes, encapsulateRoute(&netlink.Route{
				Dst:       oneAddressCIDR(segment.wireGuardIP),
				Flags:     int(netlink.FLAG_ONLINK),
				Gw:        gw,
				LinkIndex: privIface,
				Protocol:  unix.RTPROT_STATIC,
			}, enc.Strategy(), t.privateIP, tunlIface))
			// Add routes for the current segment if local is true.
			if segment.location == t.location {
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
						}, enc.Strategy(), t.privateIP, tunlIface))
					}
				}
				continue
			}
			for i := range segment.cidrs {
				// Add routes to the Pod CIDRs of nodes in other segments.
				routes = append(routes, encapsulateRoute(&netlink.Route{
					Dst:       segment.cidrs[i],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        gw,
					LinkIndex: privIface,
					Protocol:  unix.RTPROT_STATIC,
				}, enc.Strategy(), t.privateIP, tunlIface))
				// Add routes to the private IPs of nodes in other segments.
				// Number of CIDRs and private IPs always match so
				// we can reuse the loop.
				routes = append(routes, encapsulateRoute(&netlink.Route{
					Dst:       oneAddressCIDR(segment.privateIPs[i]),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        gw,
					LinkIndex: privIface,
					Protocol:  unix.RTPROT_STATIC,
				}, enc.Strategy(), t.privateIP, tunlIface))
			}
		}
		// Add routes for the allowed IPs of peers.
		for _, peer := range t.peers {
			for i := range peer.AllowedIPs {
				routes = append(routes, encapsulateRoute(&netlink.Route{
					Dst:       peer.AllowedIPs[i],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        gw,
					LinkIndex: privIface,
					Protocol:  unix.RTPROT_STATIC,
				}, enc.Strategy(), t.privateIP, tunlIface))
			}
		}
		return routes
	}
	for _, segment := range t.segments {
		// Add routes for the current segment if local is true.
		if segment.location == t.location {
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
					}, enc.Strategy(), t.privateIP, tunlIface))
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
			// Don't add routes through Kilo if the private IP
			// equals the external IP. This means that the node
			// is only accessible through an external IP and we
			// cannot encapsulate traffic to an IP through the IP.
			if segment.privateIPs[i].Equal(segment.endpoint) {
				continue
			}
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
	// Add routes for the allowed IPs of peers.
	for _, peer := range t.peers {
		for i := range peer.AllowedIPs {
			routes = append(routes, &netlink.Route{
				Dst:       peer.AllowedIPs[i],
				LinkIndex: kiloIface,
				Protocol:  unix.RTPROT_STATIC,
			})
		}
	}
	return routes
}

func encapsulateRoute(route *netlink.Route, encapsulate encapsulation.Strategy, subnet *net.IPNet, tunlIface int) *netlink.Route {
	if encapsulate == encapsulation.Always || (encapsulate == encapsulation.CrossSubnet && !subnet.Contains(route.Gw)) {
		route.LinkIndex = tunlIface
	}
	return route
}

// Conf generates a WireGuard configuration file for a given Topology.
func (t *Topology) Conf() *wireguard.Conf {
	c := &wireguard.Conf{
		Interface: &wireguard.Interface{
			PrivateKey: t.key,
			ListenPort: t.port,
		},
	}
	for _, s := range t.segments {
		if s.location == t.location {
			continue
		}
		peer := &wireguard.Peer{
			AllowedIPs: s.allowedIPs,
			Endpoint: &wireguard.Endpoint{
				IP:   s.endpoint,
				Port: uint32(t.port),
			},
			PublicKey:           s.key,
			PersistentKeepalive: s.persistentKeepalive,
		}
		c.Peers = append(c.Peers, peer)
	}
	for _, p := range t.peers {
		peer := &wireguard.Peer{
			AllowedIPs:          p.AllowedIPs,
			PersistentKeepalive: p.PersistentKeepalive,
			PublicKey:           p.PublicKey,
			Endpoint:            p.Endpoint,
		}
		c.Peers = append(c.Peers, peer)
	}
	return c
}

// AsPeer generates the WireGuard peer configuration for the local location of the given Topology.
// This configuration can be used to configure this location as a peer of another WireGuard interface.
func (t *Topology) AsPeer() *wireguard.Peer {
	for _, s := range t.segments {
		if s.location != t.location {
			continue
		}
		return &wireguard.Peer{
			AllowedIPs: s.allowedIPs,
			Endpoint: &wireguard.Endpoint{
				IP:   s.endpoint,
				Port: uint32(t.port),
			},
			PersistentKeepalive: s.persistentKeepalive,
			PublicKey:           s.key,
		}
	}
	return nil
}

// PeerConf generates a WireGuard configuration file for a given peer in a Topology.
func (t *Topology) PeerConf(name string) *wireguard.Conf {
	c := &wireguard.Conf{}
	for _, s := range t.segments {
		peer := &wireguard.Peer{
			AllowedIPs: s.allowedIPs,
			Endpoint: &wireguard.Endpoint{
				IP:   s.endpoint,
				Port: uint32(t.port),
			},
			PersistentKeepalive: s.persistentKeepalive,
			PublicKey:           s.key,
		}
		c.Peers = append(c.Peers, peer)
	}
	for _, p := range t.peers {
		if p.Name == name {
			continue
		}
		peer := &wireguard.Peer{
			AllowedIPs:          p.AllowedIPs,
			PersistentKeepalive: p.PersistentKeepalive,
			PublicKey:           p.PublicKey,
			Endpoint:            p.Endpoint,
		}
		c.Peers = append(c.Peers, peer)
	}
	return c
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

func deduplicatePeerIPs(peers []*Peer) []*Peer {
	ps := make([]*Peer, len(peers))
	ips := make(map[string]struct{})
	for i, peer := range peers {
		p := Peer{
			Name: peer.Name,
			Peer: wireguard.Peer{
				Endpoint:            peer.Endpoint,
				PersistentKeepalive: peer.PersistentKeepalive,
				PublicKey:           peer.PublicKey,
			},
		}
		for _, ip := range peer.AllowedIPs {
			if _, ok := ips[ip.String()]; ok {
				continue
			}
			p.AllowedIPs = append(p.AllowedIPs, ip)
			ips[ip.String()] = struct{}{}
		}
		ps[i] = &p
	}
	return ps
}
