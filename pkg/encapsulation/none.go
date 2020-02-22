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
	"net"

	"github.com/squat/kilo/pkg/iptables"
)

type none Strategy

// NewNone returns an new encapsulator that does not encapsulate.
func NewNone(strategy Strategy) Encapsulator {
	return none(strategy)
}

// CleanUp is a no-op.
func (n none) CleanUp() error {
	return nil
}

// Gw always returns nil.
func (n none) Gw(_, _ net.IP, _ *net.IPNet) net.IP {
	return nil
}

// Index always returns 0.
func (n none) Index() int {
	return 0
}

// Init is a no-op.
func (n none) Init(base int) error {
	return nil
}

// Rules always returns an empty list.
func (n none) Rules(_ []*net.IPNet) []iptables.Rule {
	return nil
}

// Set is a no-op.
func (n none) Set(_ *net.IPNet) error {
	return nil
}

// Strategy returns the configured strategy for encapsulation.
func (n none) Strategy() Strategy {
	return Strategy(n)
}
