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

// Strategy identifies which packets within a location should
// be encapsulated.
type Strategy string

const (
	// Never indicates that no packets within a location
	// should be encapsulated.
	Never Strategy = "never"
	// CrossSubnet indicates that only packets that
	// traverse subnets within a location should be encapsulated.
	CrossSubnet Strategy = "crosssubnet"
	// Always indicates that all packets within a location
	// should be encapsulated.
	Always Strategy = "always"
)

// Encapsulator can:
// * configure the encapsulation interface;
// * determine the gateway IP corresponding to a node;
// * get the encapsulation interface index;
// * set the interface IP address;
// * return the required IPTables rules;
// * return the encapsulation strategy; and
// * clean up any changes applied to the backend.
type Encapsulator interface {
	CleanUp() error
	Gw(net.IP, net.IP, net.IP, *net.IPNet) net.IP
	Index() int
	Init(int) error
	// LocalIP returns the local overlay IP that should be advertised
	// to other nodes. For Cilium, this is the IP of the cilium_host interface.
	LocalIP() net.IP
	Rules([]*net.IPNet) iptables.RuleSet
	Set(*net.IPNet) error
	Strategy() Strategy
}
