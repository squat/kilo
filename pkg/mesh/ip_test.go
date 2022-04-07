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

func TestNewAllocator(t *testing.T) {
	_, c1, err := net.ParseCIDR("10.1.0.0/16")
	if err != nil {
		t.Fatalf("failed to parse CIDR: %v", err)
	}
	a1 := newAllocator(*c1)
	_, c2, err := net.ParseCIDR("10.1.0.0/32")
	if err != nil {
		t.Fatalf("failed to parse CIDR: %v", err)
	}
	a2 := newAllocator(*c2)
	_, c3, err := net.ParseCIDR("10.1.0.0/31")
	if err != nil {
		t.Fatalf("failed to parse CIDR: %v", err)
	}
	a3 := newAllocator(*c3)
	for _, tc := range []struct {
		name string
		a    *allocator
		next string
	}{
		{
			name: "10.1.0.0/16 first",
			a:    a1,
			next: "10.1.0.1/16",
		},
		{
			name: "10.1.0.0/16 second",
			a:    a1,
			next: "10.1.0.2/16",
		},
		{
			name: "10.1.0.0/32",
			a:    a2,
			next: "<nil>",
		},
		{
			name: "10.1.0.0/31 first",
			a:    a3,
			next: "10.1.0.1/31",
		},
		{
			name: "10.1.0.0/31 second",
			a:    a3,
			next: "<nil>",
		},
	} {
		next := tc.a.next()
		if next.String() != tc.next {
			t.Errorf("test case %q: expected %s, got %s", tc.name, tc.next, next.String())
		}
	}
}

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

func TestIsPublic(t *testing.T) {
	for _, tc := range []struct {
		name string
		ip   net.IP
		out  bool
	}{
		{
			name: "10/8",
			ip:   net.ParseIP("10.0.0.1"),
			out:  false,
		},
		{
			name: "172.16/12",
			ip:   net.ParseIP("172.16.0.0"),
			out:  false,
		},
		{
			name: "172.16/12 random",
			ip:   net.ParseIP("172.24.135.46"),
			out:  false,
		},
		{
			name: "below 172.16/12",
			ip:   net.ParseIP("172.15.255.255"),
			out:  true,
		},
		{
			name: "above 172.16/12",
			ip:   net.ParseIP("172.160.255.255"),
			out:  true,
		},
		{
			name: "192.168/16",
			ip:   net.ParseIP("192.168.0.0"),
			out:  false,
		},
	} {
		if isPublic(tc.ip) != tc.out {
			t.Errorf("test case %q: expected %t, got %t", tc.name, tc.out, !tc.out)
		}
	}
}
