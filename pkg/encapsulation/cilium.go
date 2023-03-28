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
	"sync"

	"github.com/vishvananda/netlink"

	"github.com/squat/kilo/pkg/iptables"
)

const ciliumDeviceName = "cilium_host"

type cilium struct {
	iface    int
	strategy Strategy
	ch       chan netlink.LinkUpdate
	done     chan struct{}
	// mu guards updates to the iface field.
	mu sync.Mutex
}

// NewCilium returns an encapsulator that uses Cilium.
func NewCilium(strategy Strategy) Encapsulator {
	return &cilium{
		ch:       make(chan netlink.LinkUpdate),
		done:     make(chan struct{}),
		strategy: strategy,
	}
}

// CleanUp close done channel
func (f *cilium) CleanUp() error {
	close(f.done)
	return nil
}

// Gw returns the correct gateway IP associated with the given node.
func (f *cilium) Gw(_, _ net.IP, subnet *net.IPNet) net.IP {
	return subnet.IP
}

// Index returns the index of the Cilium interface.
func (f *cilium) Index() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.iface
}

// Init finds the Cilium interface index.
func (f *cilium) Init(_ int) error {
	if err := netlink.LinkSubscribe(f.ch, f.done); err != nil {
		return fmt.Errorf("failed to subscribe to updates to %s: %v", ciliumDeviceName, err)
	}
	go func() {
		var lu netlink.LinkUpdate
		for {
			select {
			case lu = <-f.ch:
				if lu.Attrs().Name == ciliumDeviceName {
					f.mu.Lock()
					f.iface = lu.Attrs().Index
					f.mu.Unlock()
				}
			case <-f.done:
				return
			}
		}
	}()
	i, err := netlink.LinkByName(ciliumDeviceName)
	if _, ok := err.(netlink.LinkNotFoundError); ok {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to query for Cilium interface: %v", err)
	}
	f.mu.Lock()
	f.iface = i.Attrs().Index
	f.mu.Unlock()
	return nil
}

// Rules is a no-op.
func (f *cilium) Rules(_ []*net.IPNet) iptables.RuleSet {
	return iptables.RuleSet{}
}

// Set is a no-op.
func (f *cilium) Set(_ *net.IPNet) error {
	return nil
}

// Strategy returns the configured strategy for encapsulation.
func (f *cilium) Strategy() Strategy {
	return f.strategy
}
