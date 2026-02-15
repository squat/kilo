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

package encapsulation

import (
	"net"

	"github.com/cozystack/kilo/pkg/iptables"
)

// Noop is an encapsulation that does nothing.
type Noop Strategy

// CleanUp will also do nothing.
func (n Noop) CleanUp() error {
	return nil
}

// Gw will also do nothing.
func (n Noop) Gw(_, _, _ net.IP, _ *net.IPNet) net.IP {
	return nil
}

// LocalIP will also do nothing.
func (n Noop) LocalIP() net.IP {
	return nil
}

// Index will also do nothing.
func (n Noop) Index() int {
	return 0
}

// Init will also do nothing.
func (n Noop) Init(_ int) error {
	return nil
}

// Rules will also do nothing.
func (n Noop) Rules(_ []*net.IPNet) iptables.RuleSet {
	return iptables.RuleSet{}
}

// Set will also do nothing.
func (n Noop) Set(_ *net.IPNet) error {
	return nil
}

// Strategy will finally do nothing.
func (n Noop) Strategy() Strategy {
	return Strategy(n)
}
