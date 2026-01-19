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

package mesh

import (
	"errors"
	"net"
	"sort"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/squat/kilo/pkg/wireguard"
)

const (
	logicalLocationPrefix = "location:"
	nodeLocationPrefix    = "node:"
)

// Topology represents the logical structure of the overlay network.
type Topology struct {
	// key is the private key of the node creating the topology.
	key  wgtypes.Key
	port int
	// Location is the logical location of the local host.
	location string
	segments []*segment
	peers    []*Peer

	// hostname is the hostname of the local host.
	hostname string
	// leader represents whether or not the local host
	// is the segment leader.
	leader bool
	// persistentKeepalive is the interval in seconds of the emission
	// of keepalive packets by the local node to its peers.
	persistentKeepalive time.Duration
	// privateIP is the private IP address of the local node.
	privateIP *net.IPNet
	// subnet is the Pod subnet of the local node.
	subnet *net.IPNet
	// wireGuardCIDR is the allocated CIDR of the WireGuard
	// interface of the local node within the Kilo subnet.
	// If the local node is not the leader of a location, then
	// the IP is the 0th address in the subnet, i.e. the CIDR
	// is equal to the Kilo subnet.
	wireGuardCIDR *net.IPNet
	// serviceCIDRs are the known service CIDRs of the Kubernetes cluster.
	// They are not strictly needed, however if they are known,
	// then the topology can avoid masquerading packets destined to service IPs.
	serviceCIDRs []*net.IPNet
	// discoveredEndpoints is the updated map of valid discovered Endpoints
	discoveredEndpoints map[string]*net.UDPAddr
	logger              log.Logger
}

// segment represents one logical unit in the topology that is united by one common WireGuard IP.
type segment struct {
	allowedIPs          []net.IPNet
	endpoint            *wireguard.Endpoint
	key                 wgtypes.Key
	persistentKeepalive time.Duration
	// Location is the logical location of this segment.
	location string

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
	// allowedLocationIPs are not part of the cluster and are not peers.
	// They are directly routable from nodes within the segment.
	// A classic example is a printer that ought to be routable from other locations.
	allowedLocationIPs []net.IPNet
}

// NewTopology creates a new Topology struct from a given set of nodes and peers.
func NewTopology(nodes map[string]*Node, peers map[string]*Peer, granularity Granularity, hostname string, port int, key wgtypes.Key, subnet *net.IPNet, serviceCIDRs []*net.IPNet, persistentKeepalive time.Duration, logger log.Logger) (*Topology, error) {
	if logger == nil {
		logger = log.NewNopLogger()
	}
	topoMap := make(map[string][]*Node)
	for _, node := range nodes {
		var location string
		switch granularity {
		case LogicalGranularity:
			location = logicalLocationPrefix + node.Location
			// Put node in a different location, if no private
			// IP was found.
			if node.InternalIP == nil {
				location = nodeLocationPrefix + node.Name
			}
		case FullGranularity:
			location = nodeLocationPrefix + node.Name
		}
		topoMap[location] = append(topoMap[location], node)
	}
	var localLocation string
	switch granularity {
	case LogicalGranularity:
		localLocation = logicalLocationPrefix + nodes[hostname].Location
		if nodes[hostname].InternalIP == nil {
			localLocation = nodeLocationPrefix + hostname
		}
	case FullGranularity:
		localLocation = nodeLocationPrefix + hostname
	}

	t := Topology{
		key:                 key,
		port:                port,
		hostname:            hostname,
		location:            localLocation,
		persistentKeepalive: persistentKeepalive,
		privateIP:           nodes[hostname].InternalIP,
		subnet:              nodes[hostname].Subnet,
		wireGuardCIDR:       subnet,
		serviceCIDRs:        serviceCIDRs,
		discoveredEndpoints: make(map[string]*net.UDPAddr),
		logger:              logger,
	}
	for location := range topoMap {
		// Sort the location so the result is stable.
		sort.Slice(topoMap[location], func(i, j int) bool {
			return topoMap[location][i].Name < topoMap[location][j].Name
		})
		leader := findLeader(topoMap[location])
		if location == localLocation && topoMap[location][leader].Name == hostname {
			t.leader = true
		}
		var allowedIPs []net.IPNet
		allowedLocationIPsMap := make(map[string]struct{})
		var allowedLocationIPs []net.IPNet
		var cidrs []*net.IPNet
		var hostnames []string
		var privateIPs []net.IP
		for _, node := range topoMap[location] {
			// Allowed IPs should include:
			// - the node's allocated subnet
			// - the node's WireGuard IP
			// - the node's internal IP
			// - IPs that were specified by the allowed-location-ips annotation
			if node.Subnet != nil {
				allowedIPs = append(allowedIPs, *node.Subnet)
			}
			for _, ip := range node.AllowedLocationIPs {
				if _, ok := allowedLocationIPsMap[ip.String()]; !ok {
					allowedLocationIPs = append(allowedLocationIPs, ip)
					allowedLocationIPsMap[ip.String()] = struct{}{}
				}
			}
			if node.InternalIP != nil {
				allowedIPs = append(allowedIPs, *oneAddressCIDR(node.InternalIP.IP))
				privateIPs = append(privateIPs, node.InternalIP.IP)
			}
			cidrs = append(cidrs, node.Subnet)
			hostnames = append(hostnames, node.Name)
		}
		// The sorting has no function, but makes testing easier.
		sort.Slice(allowedLocationIPs, func(i, j int) bool {
			return allowedLocationIPs[i].String() < allowedLocationIPs[j].String()
		})
		t.segments = append(t.segments, &segment{
			allowedIPs:          allowedIPs,
			endpoint:            topoMap[location][leader].Endpoint,
			key:                 topoMap[location][leader].Key,
			persistentKeepalive: topoMap[location][leader].PersistentKeepalive,
			location:            location,
			cidrs:               cidrs,
			hostnames:           hostnames,
			leader:              leader,
			privateIPs:          privateIPs,
			allowedLocationIPs:  allowedLocationIPs,
		})
		level.Debug(t.logger).Log("msg", "generated segment", "location", location, "allowedIPs", allowedIPs, "endpoint", topoMap[location][leader].Endpoint, "cidrs", cidrs, "hostnames", hostnames, "leader", leader, "privateIPs", privateIPs, "allowedLocationIPs", allowedLocationIPs)

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
	// Copy the host node DiscoveredEndpoints in the topology as a starting point.
	for key := range nodes[hostname].DiscoveredEndpoints {
		t.discoveredEndpoints[key] = nodes[hostname].DiscoveredEndpoints[key]
	}
	// Allocate IPs to the segment leaders in a stable, coordination-free manner.
	a := newAllocator(*subnet)
	for _, segment := range t.segments {
		ipNet := a.next()
		if ipNet == nil {
			return nil, errors.New("failed to allocate an IP address; ran out of IP addresses")
		}
		segment.wireGuardIP = ipNet.IP
		segment.allowedIPs = append(segment.allowedIPs, *oneAddressCIDR(ipNet.IP))
		if t.leader && segment.location == t.location {
			t.wireGuardCIDR = &net.IPNet{IP: ipNet.IP, Mask: subnet.Mask}
		}

		// Now that the topology is ordered, update the discoveredEndpoints map
		// add new ones by going through the ordered topology: segments, nodes
		for _, node := range topoMap[segment.location] {
			for key := range node.DiscoveredEndpoints {
				if _, ok := t.discoveredEndpoints[key]; !ok {
					t.discoveredEndpoints[key] = node.DiscoveredEndpoints[key]
				}
			}
		}
		// Check for intersecting IPs in allowed location IPs
		segment.allowedLocationIPs = t.filterAllowedLocationIPs(segment.allowedLocationIPs, segment.location)
	}

	level.Debug(t.logger).Log("msg", "generated topology", "location", t.location, "hostname", t.hostname, "wireGuardIP", t.wireGuardCIDR, "privateIP", t.privateIP, "subnet", t.subnet, "leader", t.leader)
	return &t, nil
}

func intersect(n1, n2 net.IPNet) bool {
	return n1.Contains(n2.IP) || n2.Contains(n1.IP)
}

func (t *Topology) filterAllowedLocationIPs(ips []net.IPNet, location string) (ret []net.IPNet) {
CheckIPs:
	for _, ip := range ips {
		for _, s := range t.segments {
			// Check if allowed location IPs are also allowed in other locations.
			if location != s.location {
				for _, i := range s.allowedLocationIPs {
					if intersect(ip, i) {
						level.Warn(t.logger).Log("msg", "overlapping allowed location IPnets", "IP", ip.String(), "IP2", i.String(), "segment-location", s.location)
						continue CheckIPs
					}
				}
			}
			// Check if allowed location IPs intersect with the allowed IPs.
			// If the allowed location IP fully contains an allowed IP, that's fine -
			// the more specific route will be used. Only warn if it's a partial overlap
			// or if the allowed IP contains the allowed location IP.
			for _, i := range s.allowedIPs {
				if intersect(ip, i) && !ip.Contains(i.IP) {
					level.Warn(t.logger).Log("msg", "overlapping allowed location IPnet with allowed IPnets", "IP", ip.String(), "IP2", i.String(), "segment-location", s.location)
					continue CheckIPs
				}
			}
			// Check if allowed location IPs intersect with the private IPs of the segment.
			// If the allowed location IP fully contains a private IP, that's fine.
			for _, i := range s.privateIPs {
				if ip.Contains(i) {
					// This is OK - the allowed location IP contains the private IP,
					// so the more specific route to the private IP will still work.
					level.Debug(t.logger).Log("msg", "allowed location IPnet contains privateIP", "IP", ip.String(), "IP2", i.String(), "segment-location", s.location)
				}
			}
		}
		// Check if allowed location IPs intersect with allowed IPs of peers.
		for _, p := range t.peers {
			for _, i := range p.AllowedIPs {
				if intersect(ip, i) {
					level.Warn(t.logger).Log("msg", "overlapping allowed location IPnet with peer IPnet", "IP", ip.String(), "IP2", i.String(), "peer", p.Name)
					continue CheckIPs
				}
			}
		}
		ret = append(ret, ip)
	}
	return
}

func (t *Topology) updateEndpoint(endpoint *wireguard.Endpoint, key wgtypes.Key, persistentKeepalive *time.Duration) *wireguard.Endpoint {
	// Do not update non-nat peers
	if persistentKeepalive == nil || *persistentKeepalive == time.Duration(0) {
		return endpoint
	}
	e, ok := t.discoveredEndpoints[key.String()]
	if ok {
		return wireguard.NewEndpointFromUDPAddr(e)
	}
	return endpoint
}

// Conf generates a WireGuard configuration file for a given Topology.
func (t *Topology) Conf() *wireguard.Conf {
	c := &wireguard.Conf{
		Config: wgtypes.Config{
			PrivateKey:   &t.key,
			ListenPort:   &t.port,
			ReplacePeers: true,
		},
	}
	for _, s := range t.segments {
		if s.location == t.location {
			continue
		}
		peer := wireguard.Peer{
			PeerConfig: wgtypes.PeerConfig{
				AllowedIPs:                  append(s.allowedIPs, s.allowedLocationIPs...),
				PersistentKeepaliveInterval: &t.persistentKeepalive,
				PublicKey:                   s.key,
				ReplaceAllowedIPs:           true,
			},
			Endpoint: t.updateEndpoint(s.endpoint, s.key, &s.persistentKeepalive),
		}
		c.Peers = append(c.Peers, peer)
	}
	for _, p := range t.peers {
		peer := wireguard.Peer{
			PeerConfig: wgtypes.PeerConfig{
				AllowedIPs:                  p.AllowedIPs,
				PersistentKeepaliveInterval: &t.persistentKeepalive,
				PresharedKey:                p.PresharedKey,
				PublicKey:                   p.PublicKey,
				ReplaceAllowedIPs:           true,
			},
			Endpoint: t.updateEndpoint(p.Endpoint, p.PublicKey, p.PersistentKeepaliveInterval),
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
		p := &wireguard.Peer{
			PeerConfig: wgtypes.PeerConfig{
				AllowedIPs: s.allowedIPs,
				PublicKey:  s.key,
			},
			Endpoint: s.endpoint,
		}
		return p
	}
	return nil
}

// PeerConf generates a WireGuard configuration file for a given peer in a Topology.
func (t *Topology) PeerConf(name string) *wireguard.Conf {
	var pka *time.Duration
	var psk *wgtypes.Key
	for i := range t.peers {
		if t.peers[i].Name == name {
			pka = t.peers[i].PersistentKeepaliveInterval
			psk = t.peers[i].PresharedKey
			break
		}
	}
	c := &wireguard.Conf{}
	for _, s := range t.segments {
		peer := wireguard.Peer{
			PeerConfig: wgtypes.PeerConfig{
				AllowedIPs:                  append(s.allowedIPs, s.allowedLocationIPs...),
				PersistentKeepaliveInterval: pka,
				PresharedKey:                psk,
				PublicKey:                   s.key,
			},
			Endpoint: t.updateEndpoint(s.endpoint, s.key, &s.persistentKeepalive),
		}
		c.Peers = append(c.Peers, peer)
	}
	for i := range t.peers {
		if t.peers[i].Name == name {
			continue
		}
		peer := wireguard.Peer{
			PeerConfig: wgtypes.PeerConfig{
				AllowedIPs:                  t.peers[i].AllowedIPs,
				PersistentKeepaliveInterval: pka,
				PublicKey:                   t.peers[i].PublicKey,
			},
			Endpoint: t.updateEndpoint(t.peers[i].Endpoint, t.peers[i].PublicKey, t.peers[i].PersistentKeepaliveInterval),
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
			if isPublic(nodes[i].Endpoint.IP()) {
				return i
			}
			leaders = append(leaders, i)

		}
		if nodes[i].Endpoint.IP() != nil && isPublic(nodes[i].Endpoint.IP()) {
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
				PeerConfig: wgtypes.PeerConfig{
					PersistentKeepaliveInterval: peer.PersistentKeepaliveInterval,
					PresharedKey:                peer.PresharedKey,
					PublicKey:                   peer.PublicKey,
				},
				Endpoint: peer.Endpoint,
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
