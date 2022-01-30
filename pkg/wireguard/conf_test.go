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

	"github.com/kylelemons/godebug/pretty"
)

func TestNewEndpoint(t *testing.T) {
	for i, tc := range []struct {
		name string
		ip   net.IP
		port int
		out  *Endpoint
	}{
		{
			name: "no ip, no port",
			out: &Endpoint{
				udpAddr: &net.UDPAddr{},
			},
		},
		{
			name: "only port",
			ip:   nil,
			port: 99,
			out: &Endpoint{
				udpAddr: &net.UDPAddr{
					Port: 99,
				},
			},
		},
		{
			name: "only ipv4",
			ip:   net.ParseIP("10.0.0.0"),
			out: &Endpoint{
				udpAddr: &net.UDPAddr{
					IP: net.ParseIP("10.0.0.0").To4(),
				},
			},
		},
		{
			name: "only ipv6",
			ip:   net.ParseIP("ff50::10"),
			out: &Endpoint{
				udpAddr: &net.UDPAddr{
					IP: net.ParseIP("ff50::10").To16(),
				},
			},
		},
		{
			name: "ipv4",
			ip:   net.ParseIP("10.0.0.0"),
			port: 1000,
			out: &Endpoint{
				udpAddr: &net.UDPAddr{
					IP:   net.ParseIP("10.0.0.0").To4(),
					Port: 1000,
				},
			},
		},
		{
			name: "ipv6",
			ip:   net.ParseIP("ff50::10"),
			port: 1000,
			out: &Endpoint{
				udpAddr: &net.UDPAddr{
					IP:   net.ParseIP("ff50::10").To16(),
					Port: 1000,
				},
			},
		},
		{
			name: "ipv6",
			ip:   net.ParseIP("fc00:f853:ccd:e793::3"),
			port: 51820,
			out: &Endpoint{
				udpAddr: &net.UDPAddr{
					IP:   net.ParseIP("fc00:f853:ccd:e793::3").To16(),
					Port: 51820,
				},
			},
		},
	} {
		out := NewEndpoint(tc.ip, tc.port)
		if diff := pretty.Compare(out, tc.out); diff != "" {
			t.Errorf("%d %s: got diff:\n%s\n", i, tc.name, diff)
		}
	}
}

func TestParseEndpoint(t *testing.T) {
	for i, tc := range []struct {
		name string
		str  string
		out  *Endpoint
	}{
		{
			name: "no ip, no port",
		},
		{
			name: "only port",
			str:  ":1000",
		},
		{
			name: "only ipv4",
			str:  "10.0.0.0",
		},
		{
			name: "only ipv6",
			str:  "ff50::10",
		},
		{
			name: "ipv4",
			str:  "10.0.0.0:1000",
			out: &Endpoint{
				udpAddr: &net.UDPAddr{
					IP:   net.ParseIP("10.0.0.0").To4(),
					Port: 1000,
				},
			},
		},
		{
			name: "ipv6",
			str:  "[ff50::10]:1000",
			out: &Endpoint{
				udpAddr: &net.UDPAddr{
					IP:   net.ParseIP("ff50::10").To16(),
					Port: 1000,
				},
			},
		},
	} {
		out := ParseEndpoint(tc.str)
		if diff := pretty.Compare(out, tc.out); diff != "" {
			t.Errorf("ParseEndpoint %s(%d): got diff:\n%s\n", tc.name, i, diff)
		}
	}
}

func TestNewEndpointFromUDPAddr(t *testing.T) {
	for i, tc := range []struct {
		name string
		u    *net.UDPAddr
		out  *Endpoint
	}{
		{
			name: "no ip, no port",
			out: &Endpoint{
				addr: "",
			},
		},
		{
			name: "only port",
			u: &net.UDPAddr{
				Port: 1000,
			},
			out: &Endpoint{
				udpAddr: &net.UDPAddr{
					Port: 1000,
				},
				addr: "",
			},
		},
		{
			name: "only ipv4",
			u: &net.UDPAddr{
				IP: net.ParseIP("10.0.0.0"),
			},
			out: &Endpoint{
				udpAddr: &net.UDPAddr{
					IP: net.ParseIP("10.0.0.0").To4(),
				},
				addr: "",
			},
		},
		{
			name: "only ipv6",
			u: &net.UDPAddr{
				IP: net.ParseIP("ff60::10"),
			},
			out: &Endpoint{
				udpAddr: &net.UDPAddr{
					IP: net.ParseIP("ff60::10").To16(),
				},
			},
		},
		{
			name: "ipv4",
			u: &net.UDPAddr{
				IP:   net.ParseIP("10.0.0.0"),
				Port: 1000,
			},
			out: &Endpoint{
				udpAddr: &net.UDPAddr{
					IP:   net.ParseIP("10.0.0.0").To4(),
					Port: 1000,
				},
			},
		},
		{
			name: "ipv6",
			u: &net.UDPAddr{
				IP:   net.ParseIP("ff50::10"),
				Port: 1000,
			},
			out: &Endpoint{
				udpAddr: &net.UDPAddr{
					IP:   net.ParseIP("ff50::10").To16(),
					Port: 1000,
				},
			},
		},
	} {
		out := NewEndpointFromUDPAddr(tc.u)
		if diff := pretty.Compare(out, tc.out); diff != "" {
			t.Errorf("ParseEndpoint %s(%d): got diff:\n%s\n", tc.name, i, diff)
		}
	}
}

func TestReady(t *testing.T) {
	for i, tc := range []struct {
		name string
		in   *Endpoint
		r    bool
	}{
		{
			name: "nil",
			r:    false,
		},
		{
			name: "no ip, no port",
			in: &Endpoint{
				addr:    "",
				udpAddr: &net.UDPAddr{},
			},
			r: false,
		},
		{
			name: "only port",
			in: &Endpoint{
				udpAddr: &net.UDPAddr{
					Port: 1000,
				},
			},
			r: false,
		},
		{
			name: "only ipv4",
			in: &Endpoint{
				udpAddr: &net.UDPAddr{
					IP: net.ParseIP("10.0.0.0"),
				},
			},
			r: false,
		},
		{
			name: "only ipv6",
			in: &Endpoint{
				udpAddr: &net.UDPAddr{
					IP: net.ParseIP("ff60::10"),
				},
			},
			r: false,
		},
		{
			name: "ipv4",
			in: &Endpoint{
				udpAddr: &net.UDPAddr{
					IP:   net.ParseIP("10.0.0.0"),
					Port: 1000,
				},
			},
			r: true,
		},
		{
			name: "ipv6",
			in: &Endpoint{
				udpAddr: &net.UDPAddr{
					IP:   net.ParseIP("ff50::10"),
					Port: 1000,
				},
			},
			r: true,
		},
	} {
		if tc.r != tc.in.Ready() {
			t.Errorf("Endpoint.Ready() %s(%d): expected=%v\tgot=%v\n", tc.name, i, tc.r, tc.in.Ready())
		}
	}
}

func TestEqual(t *testing.T) {
	for i, tc := range []struct {
		name string
		a    *Endpoint
		b    *Endpoint
		df   bool
		r    bool
	}{
		{
			name: "nil dns last",
			r:    true,
		},
		{
			name: "nil dns first",
			df:   true,
			r:    true,
		},
		{
			name: "equal: only port",
			a: &Endpoint{
				udpAddr: &net.UDPAddr{
					Port: 1000,
				},
			},
			b: &Endpoint{
				udpAddr: &net.UDPAddr{
					Port: 1000,
				},
			},
			r: true,
		},
		{
			name: "not equal: only port",
			a: &Endpoint{
				udpAddr: &net.UDPAddr{
					Port: 1000,
				},
			},
			b: &Endpoint{
				udpAddr: &net.UDPAddr{
					Port: 1001,
				},
			},
			r: false,
		},
		{
			name: "equal dns first",
			a: &Endpoint{
				udpAddr: &net.UDPAddr{
					Port: 1000,
					IP:   net.ParseIP("10.0.0.0"),
				},
				addr: "example.com:1000",
			},
			b: &Endpoint{
				udpAddr: &net.UDPAddr{
					Port: 1000,
					IP:   net.ParseIP("10.0.0.0"),
				},
				addr: "example.com:1000",
			},
			r: true,
		},
		{
			name: "equal dns last",
			a: &Endpoint{
				udpAddr: &net.UDPAddr{
					Port: 1000,
					IP:   net.ParseIP("10.0.0.0"),
				},
				addr: "example.com:1000",
			},
			b: &Endpoint{
				udpAddr: &net.UDPAddr{
					Port: 1000,
					IP:   net.ParseIP("10.0.0.0"),
				},
				addr: "foo",
			},
			r: true,
		},
		{
			name: "unequal dns first",
			a: &Endpoint{
				udpAddr: &net.UDPAddr{
					Port: 1000,
					IP:   net.ParseIP("10.0.0.0"),
				},
				addr: "example.com:1000",
			},
			b: &Endpoint{
				udpAddr: &net.UDPAddr{
					Port: 1000,
					IP:   net.ParseIP("10.0.0.0"),
				},
				addr: "foo",
			},
			df: true,
			r:  false,
		},
		{
			name: "unequal dns last",
			a: &Endpoint{
				udpAddr: &net.UDPAddr{
					Port: 1000,
					IP:   net.ParseIP("10.0.0.0"),
				},
				addr: "foo",
			},
			b: &Endpoint{
				udpAddr: &net.UDPAddr{
					Port: 1000,
					IP:   net.ParseIP("11.0.0.0"),
				},
				addr: "foo",
			},
			r: false,
		},
		{
			name: "unequal dns last empty IP",
			a: &Endpoint{
				addr: "foo",
			},
			b: &Endpoint{
				addr: "bar",
			},
			r: false,
		},
		{
			name: "equal dns last empty IP",
			a: &Endpoint{
				addr: "foo",
			},
			b: &Endpoint{
				addr: "foo",
			},
			r: true,
		},
	} {
		if out := tc.a.Equal(tc.b, tc.df); out != tc.r {
			t.Errorf("ParseEndpoint %s(%d): expected: %v\tgot: %v\n", tc.name, i, tc.r, out)
		}
	}
}
