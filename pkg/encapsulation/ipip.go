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

	"github.com/cozystack/kilo/pkg/iproute"
	"github.com/cozystack/kilo/pkg/iptables"
)

type ipip struct {
	iface    int
	strategy Strategy
}

// NewIPIP returns an encapsulator that uses IPIP.
func NewIPIP(strategy Strategy) Encapsulator {
	return &ipip{strategy: strategy}
}

// CleanUp will remove any created IPIP devices.
func (i *ipip) CleanUp() error {
	if err := iproute.DeleteAddresses(i.iface); err != nil {
		return nil
	}
	return iproute.RemoveInterface(i.iface)
}

// Gw returns the correct gateway IP associated with the given node.
func (i *ipip) Gw(_, internal, _ net.IP, _ *net.IPNet) net.IP {
	return internal
}

// LocalIP is a no-op for IPIP.
func (i *ipip) LocalIP() net.IP {
	return nil
}

// Index returns the index of the IPIP interface.
func (i *ipip) Index() int {
	return i.iface
}

// Init initializes the IPIP interface.
func (i *ipip) Init(base int) error {
	iface, err := iproute.NewIPIP(base)
	if err != nil {
		return fmt.Errorf("failed to create tunnel interface: %v", err)
	}
	if err := iproute.Set(iface, true); err != nil {
		return fmt.Errorf("failed to set tunnel interface up: %v", err)
	}
	i.iface = iface
	return nil
}

// Rules returns a set of iptables rules that are necessary
// when traffic between nodes must be encapsulated.
func (i *ipip) Rules(nodes []*net.IPNet) iptables.RuleSet {
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

// Set sets the IP address of the IPIP interface.
func (i *ipip) Set(cidr *net.IPNet) error {
	return iproute.SetAddress(i.iface, cidr)
}

// Strategy returns the configured strategy for encapsulation.
func (i *ipip) Strategy() Strategy {
	return i.strategy
}
