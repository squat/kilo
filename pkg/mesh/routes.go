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

//go:build linux
// +build linux

package mesh

import (
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/squat/kilo/pkg/encapsulation"
	"github.com/squat/kilo/pkg/iptables"
)

const kiloTableIndex = 1107

// Routes generates a slice of routes for a given Topology.
func (t *Topology) Routes(kiloIfaceName string, kiloIface, privIface, tunlIface int, local bool, enc encapsulation.Encapsulator) ([]*netlink.Route, []*netlink.Rule) {
	var routes []*netlink.Route
	var rules []*netlink.Rule
	if !t.leader {
		// Find the GW for this segment.
		// This will be the an IP of the leader.
		// In an IPIP encapsulated mesh it is the leader's private IP.
		var gw net.IP
		for _, segment := range t.segments {
			if segment.location == t.location {
				gw = enc.Gw(t.updateEndpoint(segment.endpoint, segment.key, &segment.persistentKeepalive).IP(), segment.privateIPs[segment.leader], segment.cidrs[segment.leader])
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
						// Encapsulate packets from the host's Pod subnet headed
						// to private IPs.
						if enc.Strategy() == encapsulation.Always || (enc.Strategy() == encapsulation.CrossSubnet && !t.privateIP.Contains(segment.privateIPs[i])) {
							routes = append(routes, &netlink.Route{
								Dst:       oneAddressCIDR(segment.privateIPs[i]),
								Flags:     int(netlink.FLAG_ONLINK),
								Gw:        segment.privateIPs[i],
								LinkIndex: tunlIface,
								Protocol:  unix.RTPROT_STATIC,
								Table:     kiloTableIndex,
							})
							rules = append(rules, defaultRule(&netlink.Rule{
								Src:   t.subnet,
								Dst:   oneAddressCIDR(segment.privateIPs[i]),
								Table: kiloTableIndex,
							}))
						}
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
			}
			for i := range segment.privateIPs {
				// Add routes to the private IPs of nodes in other segments.
				routes = append(routes, encapsulateRoute(&netlink.Route{
					Dst:       oneAddressCIDR(segment.privateIPs[i]),
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        gw,
					LinkIndex: privIface,
					Protocol:  unix.RTPROT_STATIC,
				}, enc.Strategy(), t.privateIP, tunlIface))
			}
			// For segments / locations other than the location of this instance of kg,
			// we need to set routes for allowed location IPs over the leader in the current location.
			for i := range segment.allowedLocationIPs {
				routes = append(routes, encapsulateRoute(&netlink.Route{
					Dst:       &segment.allowedLocationIPs[i],
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
					Dst:       &peer.AllowedIPs[i],
					Flags:     int(netlink.FLAG_ONLINK),
					Gw:        gw,
					LinkIndex: privIface,
					Protocol:  unix.RTPROT_STATIC,
				}, enc.Strategy(), t.privateIP, tunlIface))
			}
		}
		return routes, rules
	}
	for _, segment := range t.segments {
		// Add routes for the current segment if local is true.
		if (segment.location == t.location) || (t.nodeLocation != "" && segment.nodeLocation == t.nodeLocation) {
			// If the local node does not have a private IP address,
			// then skip adding routes, because the node is in its own location.
			if local && t.privateIP != nil {
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
					// Encapsulate packets from the host's Pod subnet headed
					// to private IPs.
					if enc.Strategy() == encapsulation.Always || (enc.Strategy() == encapsulation.CrossSubnet && !t.privateIP.Contains(segment.privateIPs[i])) {
						routes = append(routes, &netlink.Route{
							Dst:       oneAddressCIDR(segment.privateIPs[i]),
							Flags:     int(netlink.FLAG_ONLINK),
							Gw:        segment.privateIPs[i],
							LinkIndex: tunlIface,
							Protocol:  unix.RTPROT_STATIC,
							Table:     kiloTableIndex,
						})
						rules = append(rules, defaultRule(&netlink.Rule{
							Src:   t.subnet,
							Dst:   oneAddressCIDR(segment.privateIPs[i]),
							Table: kiloTableIndex,
						}))
						// Also encapsulate packets from the Kilo interface
						// headed to private IPs.
						rules = append(rules, defaultRule(&netlink.Rule{
							Dst:     oneAddressCIDR(segment.privateIPs[i]),
							Table:   kiloTableIndex,
							IifName: kiloIfaceName,
						}))
					}
				}
			}
			// Continuing here prevents leaders form adding routes via WireGuard to
			// nodes in their own location.
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
			if segment.privateIPs == nil || segment.privateIPs[i].Equal(t.updateEndpoint(segment.endpoint, segment.key, &segment.persistentKeepalive).IP()) {
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
		// For segments / locations other than the location of this instance of kg,
		// we need to set routes for allowed location IPs over the wg interface.
		for i := range segment.allowedLocationIPs {
			routes = append(routes, &netlink.Route{
				Dst:       &segment.allowedLocationIPs[i],
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
				Dst:       &peer.AllowedIPs[i],
				LinkIndex: kiloIface,
				Protocol:  unix.RTPROT_STATIC,
			})
		}
	}
	return routes, rules
}

// PeerRoutes generates a slice of routes and rules for a given peer in the Topology.
func (t *Topology) PeerRoutes(name string, kiloIface int, additionalAllowedIPs []net.IPNet) ([]*netlink.Route, []*netlink.Rule) {
	var routes []*netlink.Route
	var rules []*netlink.Rule
	for _, segment := range t.segments {
		for i := range segment.cidrs {
			// Add routes to the Pod CIDRs of nodes in other segments.
			routes = append(routes, &netlink.Route{
				Dst:       segment.cidrs[i],
				Flags:     int(netlink.FLAG_ONLINK),
				Gw:        segment.wireGuardIP,
				LinkIndex: kiloIface,
				Protocol:  unix.RTPROT_STATIC,
			})
		}
		for i := range segment.privateIPs {
			// Add routes to the private IPs of nodes in other segments.
			routes = append(routes, &netlink.Route{
				Dst:       oneAddressCIDR(segment.privateIPs[i]),
				Flags:     int(netlink.FLAG_ONLINK),
				Gw:        segment.wireGuardIP,
				LinkIndex: kiloIface,
				Protocol:  unix.RTPROT_STATIC,
			})
		}
		// Add routes for the allowed location IPs of all segments.
		for i := range segment.allowedLocationIPs {
			routes = append(routes, &netlink.Route{
				Dst:       &segment.allowedLocationIPs[i],
				Flags:     int(netlink.FLAG_ONLINK),
				Gw:        segment.wireGuardIP,
				LinkIndex: kiloIface,
				Protocol:  unix.RTPROT_STATIC,
			})
		}
		routes = append(routes, &netlink.Route{
			Dst:       oneAddressCIDR(segment.wireGuardIP),
			LinkIndex: kiloIface,
			Protocol:  unix.RTPROT_STATIC,
		})
	}
	// Add routes for the allowed IPs of peers.
	for _, peer := range t.peers {
		// Don't add routes to ourselves.
		if peer.Name == name {
			continue
		}
		for i := range peer.AllowedIPs {
			routes = append(routes, &netlink.Route{
				Dst:       &peer.AllowedIPs[i],
				LinkIndex: kiloIface,
				Protocol:  unix.RTPROT_STATIC,
			})
		}
	}
	for i := range additionalAllowedIPs {
		routes = append(routes, &netlink.Route{
			Dst:       &additionalAllowedIPs[i],
			Flags:     int(netlink.FLAG_ONLINK),
			Gw:        t.segments[0].wireGuardIP,
			LinkIndex: kiloIface,
			Protocol:  unix.RTPROT_STATIC,
		})
	}

	return routes, rules
}

func encapsulateRoute(route *netlink.Route, encapsulate encapsulation.Strategy, subnet *net.IPNet, tunlIface int) *netlink.Route {
	if encapsulate == encapsulation.Always || (encapsulate == encapsulation.CrossSubnet && !subnet.Contains(route.Gw)) {
		route.LinkIndex = tunlIface
	}
	return route
}

// Rules returns the iptables rules required by the local node.
func (t *Topology) Rules(cni, iptablesForwardRule bool) iptables.RuleSet {
	rules := iptables.RuleSet{}
	rules.AddToAppend(iptables.NewIPv4Chain("nat", "KILO-NAT"))
	rules.AddToAppend(iptables.NewIPv6Chain("nat", "KILO-NAT"))
	if cni {
		rules.AddToPrepend(iptables.NewRule(iptables.GetProtocol(t.subnet.IP), "nat", "POSTROUTING", "-s", t.subnet.String(), "-m", "comment", "--comment", "Kilo: jump to KILO-NAT chain", "-j", "KILO-NAT"))
		// Some linux distros or docker will set forward DROP in the filter table.
		// To still be able to have pod to pod communication we need to ALLOW packets from and to pod CIDRs within a location.
		// Leader nodes will forward packets from all nodes within a location because they act as a gateway for them.
		// Non leader nodes only need to allow packages from and to their own pod CIDR.
		if iptablesForwardRule && t.leader {
			for _, s := range t.segments {
				if s.location == t.location {
					// Make sure packets to and from pod cidrs are not dropped in the forward chain.
					for _, c := range s.cidrs {
						rules.AddToPrepend(iptables.NewRule(iptables.GetProtocol(c.IP), "filter", "FORWARD", "-m", "comment", "--comment", "Kilo: forward packets from the pod subnet", "-s", c.String(), "-j", "ACCEPT"))
						rules.AddToPrepend(iptables.NewRule(iptables.GetProtocol(c.IP), "filter", "FORWARD", "-m", "comment", "--comment", "Kilo: forward packets to the pod subnet", "-d", c.String(), "-j", "ACCEPT"))
					}
					// Make sure packets to and from allowed location IPs are not dropped in the forward chain.
					for _, c := range s.allowedLocationIPs {
						rules.AddToPrepend(iptables.NewRule(iptables.GetProtocol(c.IP), "filter", "FORWARD", "-m", "comment", "--comment", "Kilo: forward packets from allowed location IPs", "-s", c.String(), "-j", "ACCEPT"))
						rules.AddToPrepend(iptables.NewRule(iptables.GetProtocol(c.IP), "filter", "FORWARD", "-m", "comment", "--comment", "Kilo: forward packets to allowed location IPs", "-d", c.String(), "-j", "ACCEPT"))
					}
					// Make sure packets to and from private IPs are not dropped in the forward chain.
					for _, c := range s.privateIPs {
						rules.AddToPrepend(iptables.NewRule(iptables.GetProtocol(c), "filter", "FORWARD", "-m", "comment", "--comment", "Kilo: forward packets from private IPs", "-s", oneAddressCIDR(c).String(), "-j", "ACCEPT"))
						rules.AddToPrepend(iptables.NewRule(iptables.GetProtocol(c), "filter", "FORWARD", "-m", "comment", "--comment", "Kilo: forward packets to private IPs", "-d", oneAddressCIDR(c).String(), "-j", "ACCEPT"))
					}
				}
			}
		} else if iptablesForwardRule {
			rules.AddToPrepend(iptables.NewRule(iptables.GetProtocol(t.subnet.IP), "filter", "FORWARD", "-m", "comment", "--comment", "Kilo: forward packets from the node's pod subnet", "-s", t.subnet.String(), "-j", "ACCEPT"))
			rules.AddToPrepend(iptables.NewRule(iptables.GetProtocol(t.subnet.IP), "filter", "FORWARD", "-m", "comment", "--comment", "Kilo: forward packets to the node's pod subnet", "-d", t.subnet.String(), "-j", "ACCEPT"))
		}
	}
	for _, s := range t.segments {
		rules.AddToPrepend(iptables.NewRule(iptables.GetProtocol(s.wireGuardIP), "nat", "KILO-NAT", "-d", oneAddressCIDR(s.wireGuardIP).String(), "-m", "comment", "--comment", "Kilo: do not NAT packets destined for WireGuared IPs", "-j", "RETURN"))
		for _, aip := range s.allowedIPs {
			rules.AddToPrepend(iptables.NewRule(iptables.GetProtocol(aip.IP), "nat", "KILO-NAT", "-d", aip.String(), "-m", "comment", "--comment", "Kilo: do not NAT packets destined for known IPs", "-j", "RETURN"))
		}
		// Make sure packets to allowed location IPs go through the KILO-NAT chain, so they can be MASQUERADEd,
		// Otherwise packets to these destinations will reach the destination, but never find their way back.
		// We only want to NAT in locations of the corresponding allowed location IPs.
		if t.location == s.location {
			for _, alip := range s.allowedLocationIPs {
				rules.AddToPrepend(iptables.NewRule(iptables.GetProtocol(alip.IP), "nat", "POSTROUTING", "-d", alip.String(), "-m", "comment", "--comment", "Kilo: jump to NAT chain", "-j", "KILO-NAT"))
			}
		}
	}
	for _, p := range t.peers {
		for _, aip := range p.AllowedIPs {
			rules.AddToPrepend(iptables.NewRule(iptables.GetProtocol(aip.IP), "nat", "POSTROUTING", "-s", aip.String(), "-m", "comment", "--comment", "Kilo: jump to NAT chain", "-j", "KILO-NAT"))
			rules.AddToPrepend(iptables.NewRule(iptables.GetProtocol(aip.IP), "nat", "KILO-NAT", "-d", aip.String(), "-m", "comment", "--comment", "Kilo: do not NAT packets destined for peers", "-j", "RETURN"))
		}
	}
	for _, s := range t.serviceCIDRs {
		rules.AddToAppend(iptables.NewRule(iptables.GetProtocol(s.IP), "nat", "KILO-NAT", "-d", s.String(), "-m", "comment", "--comment", "Kilo: do not NAT packets destined for service CIDRs", "-j", "RETURN"))
	}
	rules.AddToAppend(iptables.NewIPv4Rule("nat", "KILO-NAT", "-m", "comment", "--comment", "Kilo: NAT remaining packets", "-j", "MASQUERADE"))
	rules.AddToAppend(iptables.NewIPv6Rule("nat", "KILO-NAT", "-m", "comment", "--comment", "Kilo: NAT remaining packets", "-j", "MASQUERADE"))
	return rules
}

func defaultRule(rule *netlink.Rule) *netlink.Rule {
	base := netlink.NewRule()
	base.Src = rule.Src
	base.Dst = rule.Dst
	base.IifName = rule.IifName
	base.Table = rule.Table
	return base
}
