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
	"net"
	"testing"
)

func TestSortIPs(t *testing.T) {
	ip1 := oneAddressCIDR(net.ParseIP("10.0.0.1"))
	ip2 := oneAddressCIDR(net.ParseIP("10.0.0.2"))
	ip3 := oneAddressCIDR(net.ParseIP("192.168.0.1"))
	ip4 := oneAddressCIDR(net.ParseIP("2001::7"))
	ip5 := oneAddressCIDR(net.ParseIP("fd68:da49:09da:b27f::"))
	for _, tc := range []struct {
		name string
		ips  []*net.IPNet
		out  []*net.IPNet
	}{
		{
			name: "single",
			ips:  []*net.IPNet{ip1},
			out:  []*net.IPNet{ip1},
		},
		{
			name: "IPv4s",
			ips:  []*net.IPNet{ip2, ip3, ip1},
			out:  []*net.IPNet{ip1, ip2, ip3},
		},
		{
			name: "IPv4 and IPv6",
			ips:  []*net.IPNet{ip4, ip1},
			out:  []*net.IPNet{ip1, ip4},
		},
		{
			name: "IPv6s",
			ips:  []*net.IPNet{ip5, ip4},
			out:  []*net.IPNet{ip4, ip5},
		},
		{
			name: "all",
			ips:  []*net.IPNet{ip3, ip4, ip2, ip5, ip1},
			out:  []*net.IPNet{ip1, ip2, ip3, ip4, ip5},
		},
	} {
		sortIPs(tc.ips)
		equal := true
		if len(tc.ips) != len(tc.out) {
			equal = false
		} else {
			for i := range tc.ips {
				if !ipNetsEqual(tc.ips[i], tc.out[i]) {
					equal = false
					break
				}
			}
		}
		if !equal {
			t.Errorf("test case %q: expected %s, got %s", tc.name, tc.out, tc.ips)
		}
	}
}
