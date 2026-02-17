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

package encapsulation

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"

	"github.com/squat/kilo/pkg/iproute"
	"github.com/squat/kilo/pkg/iptables"
)

const (
	ciliumHostIface = "cilium_host"
	// ciliumTunlIface is the kernel's default IPIP tunnel (tunl0) renamed
	// by Cilium when enable-ipip-termination is enabled.
	ciliumTunlIface = "cilium_tunl"
)

type cilium struct {
	iface      int
	strategy   Strategy
	ownsTunnel bool
}

// NewCilium returns an encapsulator that uses IPIP tunnels
// routed through Cilium's VxLAN overlay.
func NewCilium(strategy Strategy) Encapsulator {
	return &cilium{strategy: strategy}
}

// CleanUp will remove any created IPIP devices.
// If the tunnel is owned by Cilium, skip removal.
func (c *cilium) CleanUp() error {
	if !c.ownsTunnel {
		return nil
	}
	if err := iproute.DeleteAddresses(c.iface); err != nil {
		return err
	}
	return iproute.RemoveInterface(c.iface)
}

// Gw returns the correct gateway IP associated with the given node.
// It returns the Cilium internal IP so that the IPIP outer packets are routed
// through Cilium's VxLAN overlay rather than the host network.
func (c *cilium) Gw(_, _, ciliumIP net.IP, subnet *net.IPNet) net.IP {
	if ciliumIP != nil {
		return ciliumIP
	}
	return subnet.IP
}

// LocalIP returns the IP address of the cilium_host interface.
// This IP is advertised to other nodes so they can route IPIP outer
// packets through Cilium's overlay.
func (c *cilium) LocalIP() net.IP {
	iface, err := net.InterfaceByName(ciliumHostIface)
	if err != nil {
		return nil
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if ipNet, ok := a.(*net.IPNet); ok && ipNet.IP.To4() != nil {
			return ipNet.IP
		}
	}
	return nil
}

// Index returns the index of the IPIP tunnel interface.
func (c *cilium) Index() int {
	return c.iface
}

// Init initializes the IPIP tunnel interface.
// If Cilium is running with enable-ipip-termination, it renames the kernel's
// tunl0 to cilium_tunl. In that case we reuse the existing cilium_tunl.
// Otherwise we create the standard tunl0 ourselves.
func (c *cilium) Init(base int) error {
	// If Cilium created cilium_tunl (enable-ipip-termination), reuse it.
	if link, err := netlink.LinkByName(ciliumTunlIface); err == nil {
		c.iface = link.Attrs().Index
		c.ownsTunnel = false
		// Ensure the interface is UP — Cilium may leave it DOWN.
		if link.Attrs().Flags&net.FlagUp == 0 {
			if err := iproute.Set(c.iface, true); err != nil {
				return fmt.Errorf("failed to set %s up: %v", ciliumTunlIface, err)
			}
		}
		return nil
	}
	// No cilium_tunl — create standard tunl0.
	iface, err := iproute.NewIPIP(base)
	if err != nil {
		return fmt.Errorf("failed to create tunnel interface: %v", err)
	}
	if err := iproute.Set(iface, true); err != nil {
		return fmt.Errorf("failed to set tunnel interface up: %v", err)
	}
	c.iface = iface
	c.ownsTunnel = true
	return nil
}

// Rules returns a set of iptables rules that are necessary
// when traffic between nodes must be encapsulated.
func (c *cilium) Rules(nodes []*net.IPNet) iptables.RuleSet {
	rules := iptables.RuleSet{}
	proto := ipipProtocolName()
	rules.AddToAppend(iptables.NewIPv4Chain("filter", "KILO-IPIP"))
	rules.AddToAppend(iptables.NewIPv6Chain("filter", "KILO-IPIP"))
	rules.AddToAppend(iptables.NewIPv4Rule("filter", "INPUT", "-p", proto, "-m", "comment", "--comment", "Kilo: jump to IPIP chain", "-j", "KILO-IPIP"))
	rules.AddToAppend(iptables.NewIPv6Rule("filter", "INPUT", "-p", proto, "-m", "comment", "--comment", "Kilo: jump to IPIP chain", "-j", "KILO-IPIP"))
	for _, n := range nodes {
		// Accept encapsulated traffic from peers.
		rules.AddToPrepend(iptables.NewRule(iptables.GetProtocol(n.IP), "filter", "KILO-IPIP", "-s", n.String(), "-m", "comment", "--comment", "Kilo: allow IPIP traffic", "-j", "ACCEPT"))
	}
	// Drop all other IPIP traffic.
	rules.AddToAppend(iptables.NewIPv4Rule("filter", "INPUT", "-p", proto, "-m", "comment", "--comment", "Kilo: reject other IPIP traffic", "-j", "DROP"))
	rules.AddToAppend(iptables.NewIPv6Rule("filter", "INPUT", "-p", proto, "-m", "comment", "--comment", "Kilo: reject other IPIP traffic", "-j", "DROP"))

	return rules
}

// Set sets the IP address of the IPIP tunnel interface.
func (c *cilium) Set(cidr *net.IPNet) error {
	return iproute.SetAddress(c.iface, cidr)
}

// Strategy returns the configured strategy for encapsulation.
func (c *cilium) Strategy() Strategy {
	return c.strategy
}
