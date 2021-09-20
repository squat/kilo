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

package wireguard

import (
	"net"
	"testing"
)

func TestCompareEndpoint(t *testing.T) {
	for _, tc := range []struct {
		name     string
		a        *Endpoint
		b        *Endpoint
		dnsFirst bool
		out      bool
	}{
		{
			name: "both nil",
			a:    nil,
			b:    nil,
			out:  true,
		},
		{
			name: "a nil",
			a:    nil,
			b:    &Endpoint{},
			out:  false,
		},
		{
			name: "b nil",
			a:    &Endpoint{},
			b:    nil,
			out:  false,
		},
		{
			name: "zero",
			a:    &Endpoint{},
			b:    &Endpoint{},
			out:  true,
		},
		{
			name: "diff port",
			a:    &Endpoint{Port: 1234},
			b:    &Endpoint{Port: 5678},
			out:  false,
		},
		{
			name: "same IP",
			a:    &Endpoint{Port: 1234, DNSOrIP: DNSOrIP{IP: net.ParseIP("192.168.0.1")}},
			b:    &Endpoint{Port: 1234, DNSOrIP: DNSOrIP{IP: net.ParseIP("192.168.0.1")}},
			out:  true,
		},
		{
			name: "diff IP",
			a:    &Endpoint{Port: 1234, DNSOrIP: DNSOrIP{IP: net.ParseIP("192.168.0.1")}},
			b:    &Endpoint{Port: 1234, DNSOrIP: DNSOrIP{IP: net.ParseIP("192.168.0.2")}},
			out:  false,
		},
		{
			name: "same IP ignore DNS",
			a:    &Endpoint{Port: 1234, DNSOrIP: DNSOrIP{IP: net.ParseIP("192.168.0.1"), DNS: "a"}},
			b:    &Endpoint{Port: 1234, DNSOrIP: DNSOrIP{IP: net.ParseIP("192.168.0.1"), DNS: "b"}},
			out:  true,
		},
		{
			name: "no IP check DNS",
			a:    &Endpoint{Port: 1234, DNSOrIP: DNSOrIP{DNS: "a"}},
			b:    &Endpoint{Port: 1234, DNSOrIP: DNSOrIP{DNS: "b"}},
			out:  false,
		},
		{
			name: "no IP check DNS (same)",
			a:    &Endpoint{Port: 1234, DNSOrIP: DNSOrIP{DNS: "a"}},
			b:    &Endpoint{Port: 1234, DNSOrIP: DNSOrIP{DNS: "a"}},
			out:  true,
		},
		{
			name:     "DNS first, ignore IP",
			a:        &Endpoint{Port: 1234, DNSOrIP: DNSOrIP{IP: net.ParseIP("192.168.0.1"), DNS: "a"}},
			b:        &Endpoint{Port: 1234, DNSOrIP: DNSOrIP{IP: net.ParseIP("192.168.0.2"), DNS: "a"}},
			dnsFirst: true,
			out:      true,
		},
		{
			name:     "DNS first",
			a:        &Endpoint{Port: 1234, DNSOrIP: DNSOrIP{DNS: "a"}},
			b:        &Endpoint{Port: 1234, DNSOrIP: DNSOrIP{DNS: "b"}},
			dnsFirst: true,
			out:      false,
		},
		{
			name:     "DNS first, no DNS compare IP",
			a:        &Endpoint{Port: 1234, DNSOrIP: DNSOrIP{IP: net.ParseIP("192.168.0.1"), DNS: ""}},
			b:        &Endpoint{Port: 1234, DNSOrIP: DNSOrIP{IP: net.ParseIP("192.168.0.2"), DNS: ""}},
			dnsFirst: true,
			out:      false,
		},
		{
			name:     "DNS first, no DNS compare IP (same)",
			a:        &Endpoint{Port: 1234, DNSOrIP: DNSOrIP{IP: net.ParseIP("192.168.0.1"), DNS: ""}},
			b:        &Endpoint{Port: 1234, DNSOrIP: DNSOrIP{IP: net.ParseIP("192.168.0.1"), DNS: ""}},
			dnsFirst: true,
			out:      true,
		},
	} {
		equal := tc.a.Equal(tc.b, tc.dnsFirst)
		if equal != tc.out {
			t.Errorf("test case %q: expected %t, got %t", tc.name, tc.out, equal)
		}
	}
}
