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
	"testing"
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
