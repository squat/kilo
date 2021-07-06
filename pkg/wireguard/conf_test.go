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

package wireguard

import (
	"net"
	"testing"

	"github.com/kylelemons/godebug/pretty"
)

func TestCompareConf(t *testing.T) {
	for _, tc := range []struct {
		name string
		a    []byte
		b    []byte
		out  bool
	}{
		{
			name: "empty",
			a:    []byte{},
			b:    []byte{},
			out:  true,
		},
		{
			name: "key and value order",
			a: []byte(`[Interface]
		PrivateKey = private
		ListenPort = 51820

		[Peer]
		Endpoint = 10.1.0.2:51820
		PresharedKey = psk
		PublicKey = key
		AllowedIPs = 10.2.2.0/24, 192.168.0.1/32, 10.2.3.0/24, 192.168.0.2/32, 10.4.0.2/32
		`),
			b: []byte(`[Interface]
		ListenPort = 51820
		PrivateKey = private

		[Peer]
		PublicKey = key
		AllowedIPs = 192.168.0.1/32, 10.2.3.0/24, 192.168.0.2/32, 10.4.0.2/32, 10.2.2.0/24
		PresharedKey = psk
		Endpoint = 10.1.0.2:51820
		`),
			out: true,
		},
		{
			name: "whitespace",
			a: []byte(`[Interface]
		PrivateKey = private
		ListenPort = 51820

		[Peer]
		Endpoint = 10.1.0.2:51820
		PresharedKey = psk
		PublicKey = key
		AllowedIPs = 10.2.2.0/24, 192.168.0.1/32, 10.2.3.0/24, 192.168.0.2/32, 10.4.0.2/32
		`),
			b: []byte(`[Interface]
		PrivateKey=private
		ListenPort=51820
		[Peer]
		Endpoint=10.1.0.2:51820
		PresharedKey = psk
		PublicKey=key
		AllowedIPs=10.2.2.0/24,192.168.0.1/32,10.2.3.0/24,192.168.0.2/32,10.4.0.2/32
		`),
			out: true,
		},
		{
			name: "missing key",
			a: []byte(`[Interface]
		PrivateKey = private
		ListenPort = 51820

		[Peer]
		Endpoint = 10.1.0.2:51820
		PublicKey = key
		AllowedIPs = 10.2.2.0/24, 192.168.0.1/32, 10.2.3.0/24, 192.168.0.2/32, 10.4.0.2/32
		`),
			b: []byte(`[Interface]
		PrivateKey = private
		ListenPort = 51820

		[Peer]
		PublicKey = key
		AllowedIPs = 10.2.2.0/24, 192.168.0.1/32, 10.2.3.0/24, 192.168.0.2/32, 10.4.0.2/32
		`),
			out: false,
		},
		{
			name: "different value",
			a: []byte(`[Interface]
		PrivateKey = private
		ListenPort = 51820

		[Peer]
		Endpoint = 10.1.0.2:51820
		PublicKey = key
		AllowedIPs = 10.2.2.0/24, 192.168.0.1/32, 10.2.3.0/24, 192.168.0.2/32, 10.4.0.2/32
		`),
			b: []byte(`[Interface]
		PrivateKey = private
		ListenPort = 51820

		[Peer]
		Endpoint = 10.1.0.2:51820
		PublicKey = key2
		AllowedIPs = 10.2.2.0/24, 192.168.0.1/32, 10.2.3.0/24, 192.168.0.2/32, 10.4.0.2/32
		`),
			out: false,
		},
		{
			name: "section order",
			a: []byte(`[Interface]
		PrivateKey = private
		ListenPort = 51820

		[Peer]
		Endpoint = 10.1.0.2:51820
		PresharedKey = psk
		PublicKey = key
		AllowedIPs = 10.2.2.0/24, 192.168.0.1/32, 10.2.3.0/24, 192.168.0.2/32, 10.4.0.2/32
		`),
			b: []byte(`[Peer]
		Endpoint = 10.1.0.2:51820
		PresharedKey = psk
		PublicKey = key
		AllowedIPs = 10.2.2.0/24, 192.168.0.1/32, 10.2.3.0/24, 192.168.0.2/32, 10.4.0.2/32

		[Interface]
		PrivateKey = private
		ListenPort = 51820
		`),
			out: true,
		},
		{
			name: "out of order peers",
			a: []byte(`[Interface]
		PrivateKey = private
		ListenPort = 51820

		[Peer]
		Endpoint = 10.1.0.2:51820
		PresharedKey = psk2
		PublicKey = key2
		AllowedIPs = 10.2.2.0/24, 192.168.0.1/32, 10.2.3.0/24, 192.168.0.2/32, 10.4.0.2/32

		[Peer]
		Endpoint = 10.1.0.2:51820
		PresharedKey = psk1
		PublicKey = key1
		AllowedIPs = 10.2.2.0/24, 192.168.0.1/32, 10.2.3.0/24, 192.168.0.2/32, 10.4.0.2/32
		`),
			b: []byte(`[Interface]
		PrivateKey = private
		ListenPort = 51820

		[Peer]
		Endpoint = 10.1.0.2:51820
		PresharedKey = psk1
		PublicKey = key1
		AllowedIPs = 10.2.2.0/24, 192.168.0.1/32, 10.2.3.0/24, 192.168.0.2/32, 10.4.0.2/32

		[Peer]
		Endpoint = 10.1.0.2:51820
		PresharedKey = psk2
		PublicKey = key2
		AllowedIPs = 10.2.2.0/24, 192.168.0.1/32, 10.2.3.0/24, 192.168.0.2/32, 10.4.0.2/32
		`),
			out: true,
		},
		{
			name: "one empty",
			a: []byte(`[Interface]
		PrivateKey = private
		ListenPort = 51820

		[Peer]
		Endpoint = 10.1.0.2:51820
		PresharedKey = psk
		PublicKey = key
		AllowedIPs = 10.2.2.0/24, 192.168.0.1/32, 10.2.3.0/24, 192.168.0.2/32, 10.4.0.2/32
		`),
			b:   []byte(``),
			out: false,
		},
	} {
		equal := Parse(tc.a).Equal(Parse(tc.b))
		if equal != tc.out {
			t.Errorf("test case %q: expected %t, got %t", tc.name, tc.out, equal)
		}
	}
}

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

func TestCompareDumpConf(t *testing.T) {
	for _, tc := range []struct {
		name string
		d    []byte
		c    []byte
	}{
		{
			name: "empty",
			d:    []byte{},
			c:    []byte{},
		},
		{
			name: "redacted copy from wg output",
			d: []byte(`private	B7qk8EMlob0nfado0ABM6HulUV607r4yqtBKjhap7S4=	51820	off
key1	(none)	10.254.1.1:51820	100.64.1.0/24,192.168.0.125/32,10.4.0.1/32	1619012801	67048	34952	10
key2	(none)	10.254.2.1:51820	100.64.4.0/24,10.69.76.55/32,100.64.3.0/24,10.66.25.131/32,10.4.0.2/32	1619013058	1134456	10077852	10`),
			c: []byte(`[Interface]
		ListenPort = 51820
		PrivateKey = private

		[Peer]
		PublicKey = key1
		AllowedIPs = 100.64.1.0/24, 192.168.0.125/32, 10.4.0.1/32
		Endpoint = 10.254.1.1:51820
		PersistentKeepalive = 10

		[Peer]
		PublicKey = key2
		AllowedIPs = 100.64.4.0/24, 10.69.76.55/32, 100.64.3.0/24, 10.66.25.131/32, 10.4.0.2/32
		Endpoint = 10.254.2.1:51820
		PersistentKeepalive = 10`),
		},
	} {

		dumpConf, _ := ParseDump(tc.d)
		conf := Parse(tc.c)
		// Equal will ignore runtime fields and only compare configuration fields.
		if !dumpConf.Equal(conf) {
			diff := pretty.Compare(dumpConf, conf)
			t.Errorf("test case %q: got diff: %v", tc.name, diff)
		}
	}
}
