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
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/squat/kilo/pkg/wireguard"
)

func mustKey() wgtypes.Key {
	if k, err := wgtypes.GeneratePrivateKey(); err != nil {
		panic(err.Error())
	} else {
		return k
	}
}

var key = mustKey()

func TestReady(t *testing.T) {
	internalIP := oneAddressCIDR(net.ParseIP("1.1.1.1"))
	externalIP := oneAddressCIDR(net.ParseIP("2.2.2.2"))
	for _, tc := range []struct {
		name  string
		node  *Node
		ready bool
	}{
		{
			name:  "nil",
			node:  nil,
			ready: false,
		},
		{
			name: "empty fields",
			node: &Node{
				CheckLastSeen: true,
			},
			ready: false,
		},
		{
			name: "empty endpoint",
			node: &Node{
				InternalIP:    internalIP,
				Key:           key,
				Subnet:        &net.IPNet{IP: net.ParseIP("10.2.0.0"), Mask: net.CIDRMask(16, 32)},
				CheckLastSeen: true,
			},
			ready: false,
		},
		{
			name: "empty endpoint IP",
			node: &Node{
				Endpoint:      wireguard.NewEndpoint(nil, DefaultKiloPort),
				InternalIP:    internalIP,
				Key:           wgtypes.Key{},
				Subnet:        &net.IPNet{IP: net.ParseIP("10.2.0.0"), Mask: net.CIDRMask(16, 32)},
				CheckLastSeen: true,
			},
			ready: false,
		},
		{
			name: "empty endpoint port",
			node: &Node{
				Endpoint:      wireguard.NewEndpoint(externalIP.IP, 0),
				InternalIP:    internalIP,
				Key:           wgtypes.Key{},
				Subnet:        &net.IPNet{IP: net.ParseIP("10.2.0.0"), Mask: net.CIDRMask(16, 32)},
				CheckLastSeen: true,
			},
			ready: false,
		},
		{
			name: "empty internal IP",
			node: &Node{
				Endpoint:      wireguard.NewEndpoint(externalIP.IP, DefaultKiloPort),
				Key:           wgtypes.Key{},
				Subnet:        &net.IPNet{IP: net.ParseIP("10.2.0.0"), Mask: net.CIDRMask(16, 32)},
				CheckLastSeen: true,
			},
			ready: false,
		},
		{
			name: "empty key",
			node: &Node{
				Endpoint:      wireguard.NewEndpoint(externalIP.IP, DefaultKiloPort),
				InternalIP:    internalIP,
				Subnet:        &net.IPNet{IP: net.ParseIP("10.2.0.0"), Mask: net.CIDRMask(16, 32)},
				CheckLastSeen: true,
			},
			ready: false,
		},
		{
			name: "empty subnet",
			node: &Node{
				Endpoint:      wireguard.NewEndpoint(externalIP.IP, DefaultKiloPort),
				InternalIP:    internalIP,
				Key:           wgtypes.Key{},
				CheckLastSeen: true,
			},
			ready: false,
		},
		{
			name: "valid",
			node: &Node{
				Endpoint:      wireguard.NewEndpoint(externalIP.IP, DefaultKiloPort),
				InternalIP:    internalIP,
				Key:           key,
				LastSeen:      time.Now().Unix(),
				CheckLastSeen: true,
				Subnet:        &net.IPNet{IP: net.ParseIP("10.2.0.0"), Mask: net.CIDRMask(16, 32)},
			},
			ready: true,
		},
	} {
		ready := tc.node.Ready()
		if ready != tc.ready {
			t.Errorf("test case %q: expected %t, got %t", tc.name, tc.ready, ready)
		}
	}
}
