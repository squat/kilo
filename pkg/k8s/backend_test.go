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

package k8s

import (
	"net"
	"testing"
	"time"

	"github.com/kylelemons/godebug/pretty"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	v1 "k8s.io/api/core/v1"

	"github.com/squat/kilo/pkg/k8s/apis/kilo/v1alpha1"
	"github.com/squat/kilo/pkg/mesh"
	"github.com/squat/kilo/pkg/wireguard"
)

func mustKey() (k wgtypes.Key) {
	var err error
	if k, err = wgtypes.GeneratePrivateKey(); err != nil {
		panic(err.Error())
	}
	return
}

func mustPSKKey() (key *wgtypes.Key) {
	if k, err := wgtypes.GenerateKey(); err != nil {
		panic(err.Error())
	} else {
		key = &k
	}
	return
}

var (
	fooKey = mustKey()
	pskKey = mustPSKKey()
	second = time.Second
	zero   = time.Duration(0)
)

func TestTranslateNode(t *testing.T) {
	for _, tc := range []struct {
		name        string
		annotations map[string]string
		labels      map[string]string
		out         *mesh.Node
		subnet      string
	}{
		{
			name:        "empty",
			annotations: nil,
			out: &mesh.Node{
				CheckLastSeen: true,
			},
		},
		{
			name: "invalid ips",
			annotations: map[string]string{
				endpointAnnotationKey:   "10.0.0.1",
				internalIPAnnotationKey: "foo",
			},
			out: &mesh.Node{
				CheckLastSeen: true,
			},
		},
		{
			name: "valid ips",
			annotations: map[string]string{
				endpointAnnotationKey:   "10.0.0.1:51820",
				internalIPAnnotationKey: "10.0.0.2/32",
			},
			out: &mesh.Node{
				Endpoint:      wireguard.NewEndpoint(net.ParseIP("10.0.0.1").To4(), mesh.DefaultKiloPort),
				InternalIP:    &net.IPNet{IP: net.ParseIP("10.0.0.2").To4(), Mask: net.CIDRMask(32, 32)},
				CheckLastSeen: true,
			},
		},
		{
			name: "valid ips with ipv6",
			annotations: map[string]string{
				endpointAnnotationKey:   "[ff10::10]:51820",
				internalIPAnnotationKey: "ff60::10/64",
			},
			out: &mesh.Node{
				Endpoint:      wireguard.NewEndpoint(net.ParseIP("ff10::10").To16(), mesh.DefaultKiloPort),
				InternalIP:    &net.IPNet{IP: net.ParseIP("ff60::10").To16(), Mask: net.CIDRMask(64, 128)},
				CheckLastSeen: true,
			},
		},
		{
			name:        "invalid subnet",
			annotations: map[string]string{},
			out: &mesh.Node{
				CheckLastSeen: true,
			},
			subnet: "foo",
		},
		{
			name:        "normalize subnet",
			annotations: map[string]string{},
			out: &mesh.Node{
				Subnet:        &net.IPNet{IP: net.ParseIP("10.2.0.0").To4(), Mask: net.CIDRMask(24, 32)},
				CheckLastSeen: true,
			},
			subnet: "10.2.0.1/24",
		},
		{
			name:        "valid subnet",
			annotations: map[string]string{},
			out: &mesh.Node{
				Subnet:        &net.IPNet{IP: net.ParseIP("10.2.1.0").To4(), Mask: net.CIDRMask(24, 32)},
				CheckLastSeen: true,
			},
			subnet: "10.2.1.0/24",
		},
		{
			name: "region",
			labels: map[string]string{
				RegionLabelKey: "a",
			},
			out: &mesh.Node{
				Location:      "a",
				CheckLastSeen: true,
			},
		},
		{
			name: "region override",
			annotations: map[string]string{
				locationAnnotationKey: "b",
			},
			labels: map[string]string{
				RegionLabelKey: "a",
			},
			out: &mesh.Node{
				Location:      "b",
				CheckLastSeen: true,
			},
		},
		{
			name: "invalid endpoint override",
			annotations: map[string]string{
				endpointAnnotationKey:      "10.0.0.1:51820",
				forceEndpointAnnotationKey: "-10.0.0.2:51821",
			},
			out: &mesh.Node{
				Endpoint:      wireguard.NewEndpoint(net.ParseIP("10.0.0.1").To4(), mesh.DefaultKiloPort),
				CheckLastSeen: true,
			},
		},
		{
			name: "endpoint override",
			annotations: map[string]string{
				endpointAnnotationKey:      "10.0.0.1:51820",
				forceEndpointAnnotationKey: "10.0.0.2:51821",
			},
			out: &mesh.Node{
				Endpoint:      wireguard.NewEndpoint(net.ParseIP("10.0.0.2").To4(), 51821),
				CheckLastSeen: true,
			},
		},
		{
			name: "wireguard persistent keepalive override",
			annotations: map[string]string{
				persistentKeepaliveKey: "25",
			},
			out: &mesh.Node{
				PersistentKeepalive: 25 * time.Second,
				CheckLastSeen:       true,
			},
		},
		{
			name: "invalid internal IP override",
			annotations: map[string]string{
				internalIPAnnotationKey:      "10.1.0.1/24",
				forceInternalIPAnnotationKey: "-10.1.0.2/24",
			},
			out: &mesh.Node{
				InternalIP:    &net.IPNet{IP: net.ParseIP("10.1.0.1").To4(), Mask: net.CIDRMask(24, 32)},
				NoInternalIP:  false,
				CheckLastSeen: true,
			},
		},
		{
			name: "internal IP override",
			annotations: map[string]string{
				internalIPAnnotationKey:      "10.1.0.1/24",
				forceInternalIPAnnotationKey: "10.1.0.2/24",
			},
			out: &mesh.Node{
				InternalIP:    &net.IPNet{IP: net.ParseIP("10.1.0.2").To4(), Mask: net.CIDRMask(24, 32)},
				NoInternalIP:  false,
				CheckLastSeen: true,
			},
		},
		{
			name: "invalid time",
			annotations: map[string]string{
				lastSeenAnnotationKey: "foo",
			},
			out: &mesh.Node{
				CheckLastSeen: true,
			},
		},
		{
			name: "complete",
			annotations: map[string]string{
				endpointAnnotationKey:        "10.0.0.1:51820",
				forceEndpointAnnotationKey:   "10.0.0.2:51821",
				forceInternalIPAnnotationKey: "10.1.0.2/32",
				internalIPAnnotationKey:      "10.1.0.1/32",
				keyAnnotationKey:             fooKey.String(),
				lastSeenAnnotationKey:        "1000000000",
				leaderAnnotationKey:          "",
				locationAnnotationKey:        "b",
				persistentKeepaliveKey:       "25",
				wireGuardIPAnnotationKey:     "10.4.0.1/16",
			},
			labels: map[string]string{
				RegionLabelKey: "a",
			},
			out: &mesh.Node{
				Endpoint:            wireguard.NewEndpoint(net.ParseIP("10.0.0.2").To4(), 51821),
				NoInternalIP:        false,
				InternalIP:          &net.IPNet{IP: net.ParseIP("10.1.0.2").To4(), Mask: net.CIDRMask(32, 32)},
				Key:                 fooKey,
				LastSeen:            1000000000,
				CheckLastSeen:       true,
				Leader:              true,
				Location:            "b",
				PersistentKeepalive: 25 * time.Second,
				Subnet:              &net.IPNet{IP: net.ParseIP("10.2.1.0").To4(), Mask: net.CIDRMask(24, 32)},
				WireGuardIP:         &net.IPNet{IP: net.ParseIP("10.4.0.1").To4(), Mask: net.CIDRMask(16, 32)},
			},
			subnet: "10.2.1.0/24",
		},
		{
			name: "complete with ipv6",
			annotations: map[string]string{
				endpointAnnotationKey:        "10.0.0.1:51820",
				forceEndpointAnnotationKey:   "[1100::10]:51821",
				forceInternalIPAnnotationKey: "10.1.0.2/32",
				internalIPAnnotationKey:      "10.1.0.1/32",
				keyAnnotationKey:             fooKey.String(),
				lastSeenAnnotationKey:        "1000000000",
				leaderAnnotationKey:          "",
				locationAnnotationKey:        "b",
				persistentKeepaliveKey:       "25",
				wireGuardIPAnnotationKey:     "10.4.0.1/16",
			},
			labels: map[string]string{
				RegionLabelKey: "a",
			},
			out: &mesh.Node{
				Endpoint:            wireguard.NewEndpoint(net.ParseIP("1100::10"), 51821),
				NoInternalIP:        false,
				InternalIP:          &net.IPNet{IP: net.ParseIP("10.1.0.2"), Mask: net.CIDRMask(32, 32)},
				Key:                 fooKey,
				LastSeen:            1000000000,
				CheckLastSeen:       true,
				Leader:              true,
				Location:            "b",
				PersistentKeepalive: 25 * time.Second,
				Subnet:              &net.IPNet{IP: net.ParseIP("10.2.1.0"), Mask: net.CIDRMask(24, 32)},
				WireGuardIP:         &net.IPNet{IP: net.ParseIP("10.4.0.1"), Mask: net.CIDRMask(16, 32)},
			},
			subnet: "10.2.1.0/24",
		},
		{
			name: "no InternalIP",
			annotations: map[string]string{
				endpointAnnotationKey:    "10.0.0.1:51820",
				internalIPAnnotationKey:  "",
				keyAnnotationKey:         fooKey.String(),
				lastSeenAnnotationKey:    "1000000000",
				locationAnnotationKey:    "b",
				persistentKeepaliveKey:   "25",
				wireGuardIPAnnotationKey: "10.4.0.1/16",
			},
			labels: map[string]string{
				RegionLabelKey: "a",
			},
			out: &mesh.Node{
				Endpoint:            wireguard.NewEndpoint(net.ParseIP("10.0.0.1"), 51820),
				InternalIP:          nil,
				Key:                 fooKey,
				LastSeen:            1000000000,
				CheckLastSeen:       true,
				Leader:              false,
				Location:            "b",
				PersistentKeepalive: 25 * time.Second,
				Subnet:              &net.IPNet{IP: net.ParseIP("10.2.1.0"), Mask: net.CIDRMask(24, 32)},
				WireGuardIP:         &net.IPNet{IP: net.ParseIP("10.4.0.1"), Mask: net.CIDRMask(16, 32)},
			},
			subnet: "10.2.1.0/24",
		},
		{
			name: "Force no internal IP",
			annotations: map[string]string{
				endpointAnnotationKey:        "10.0.0.1:51820",
				internalIPAnnotationKey:      "10.1.0.1/32",
				forceInternalIPAnnotationKey: "",
				keyAnnotationKey:             fooKey.String(),
				lastSeenAnnotationKey:        "1000000000",
				locationAnnotationKey:        "b",
				persistentKeepaliveKey:       "25",
				wireGuardIPAnnotationKey:     "10.4.0.1/16",
			},
			labels: map[string]string{
				RegionLabelKey: "a",
			},
			out: &mesh.Node{
				Endpoint:            wireguard.NewEndpoint(net.ParseIP("10.0.0.1"), 51820),
				NoInternalIP:        true,
				InternalIP:          nil,
				Key:                 fooKey,
				LastSeen:            1000000000,
				CheckLastSeen:       true,
				Leader:              false,
				Location:            "b",
				PersistentKeepalive: 25 * time.Second,
				Subnet:              &net.IPNet{IP: net.ParseIP("10.2.1.0"), Mask: net.CIDRMask(24, 32)},
				WireGuardIP:         &net.IPNet{IP: net.ParseIP("10.4.0.1"), Mask: net.CIDRMask(16, 32)},
			},
			subnet: "10.2.1.0/24",
		},
	} {
		n := &v1.Node{}
		n.ObjectMeta.Annotations = tc.annotations
		n.ObjectMeta.Labels = tc.labels
		n.Spec.PodCIDR = tc.subnet
		node := translateNode(n, RegionLabelKey, true)
		if diff := pretty.Compare(node, tc.out); diff != "" {
			t.Errorf("test case %q: got diff: %v", tc.name, diff)
		}
	}
}

func TestTranslatePeer(t *testing.T) {
	for _, tc := range []struct {
		name string
		out  *mesh.Peer
		spec v1alpha1.PeerSpec
	}{
		{
			name: "empty",
			out: &mesh.Peer{
				Peer: wireguard.Peer{
					PeerConfig: wgtypes.PeerConfig{
						PersistentKeepaliveInterval: &zero,
					},
				},
			},
		},
		{
			name: "invalid ips",
			spec: v1alpha1.PeerSpec{
				AllowedIPs: []string{
					"10.0.0.1",
					"foo",
				},
			},
			out: &mesh.Peer{
				Peer: wireguard.Peer{
					PeerConfig: wgtypes.PeerConfig{
						PersistentKeepaliveInterval: &zero,
					},
				},
			},
		},
		{
			name: "valid ips",
			spec: v1alpha1.PeerSpec{
				AllowedIPs: []string{
					"10.0.0.1/24",
					"10.0.0.2/32",
				},
			},
			out: &mesh.Peer{
				Peer: wireguard.Peer{
					PeerConfig: wgtypes.PeerConfig{
						AllowedIPs: []net.IPNet{
							{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)},
							{IP: net.ParseIP("10.0.0.2"), Mask: net.CIDRMask(32, 32)},
						},
						PersistentKeepaliveInterval: &zero,
					},
				},
			},
		},
		{
			name: "invalid endpoint ip",
			spec: v1alpha1.PeerSpec{
				Endpoint: &v1alpha1.PeerEndpoint{
					DNSOrIP: v1alpha1.DNSOrIP{
						IP: "foo",
					},
					Port: mesh.DefaultKiloPort,
				},
			},
			out: &mesh.Peer{
				Peer: wireguard.Peer{
					PeerConfig: wgtypes.PeerConfig{
						PersistentKeepaliveInterval: &zero,
					},
				},
			},
		},
		{
			name: "only endpoint port",
			spec: v1alpha1.PeerSpec{
				Endpoint: &v1alpha1.PeerEndpoint{
					Port: mesh.DefaultKiloPort,
				},
			},
			out: &mesh.Peer{
				Peer: wireguard.Peer{
					PeerConfig: wgtypes.PeerConfig{
						PersistentKeepaliveInterval: &zero,
					},
				},
			},
		},
		{
			name: "valid endpoint ip",
			spec: v1alpha1.PeerSpec{
				Endpoint: &v1alpha1.PeerEndpoint{
					DNSOrIP: v1alpha1.DNSOrIP{
						IP: "10.0.0.1",
					},
					Port: mesh.DefaultKiloPort,
				},
			},
			out: &mesh.Peer{
				Peer: wireguard.Peer{
					PeerConfig: wgtypes.PeerConfig{
						PersistentKeepaliveInterval: &zero,
					},
					Endpoint: wireguard.NewEndpoint(net.ParseIP("10.0.0.1").To4(), mesh.DefaultKiloPort),
				},
			},
		},
		{
			name: "valid endpoint ipv6",
			spec: v1alpha1.PeerSpec{
				Endpoint: &v1alpha1.PeerEndpoint{
					DNSOrIP: v1alpha1.DNSOrIP{
						IP: "ff60::2",
					},
					Port: mesh.DefaultKiloPort,
				},
			},
			out: &mesh.Peer{
				Peer: wireguard.Peer{
					PeerConfig: wgtypes.PeerConfig{
						PersistentKeepaliveInterval: &zero,
					},
					Endpoint: wireguard.NewEndpoint(net.ParseIP("ff60::2").To16(), mesh.DefaultKiloPort),
				},
			},
		},
		{
			name: "valid endpoint DNS",
			spec: v1alpha1.PeerSpec{
				Endpoint: &v1alpha1.PeerEndpoint{
					DNSOrIP: v1alpha1.DNSOrIP{
						DNS: "example.com",
					},
					Port: mesh.DefaultKiloPort,
				},
			},
			out: &mesh.Peer{
				Peer: wireguard.Peer{
					Endpoint: wireguard.ParseEndpoint("example.com:51820"),
					PeerConfig: wgtypes.PeerConfig{
						PersistentKeepaliveInterval: &zero,
					},
				},
			},
		},
		{
			name: "empty key",
			spec: v1alpha1.PeerSpec{
				PublicKey: "",
			},
			out: &mesh.Peer{
				Peer: wireguard.Peer{
					PeerConfig: wgtypes.PeerConfig{
						PersistentKeepaliveInterval: &zero,
					},
				},
			},
		},
		{
			name: "valid key",
			spec: v1alpha1.PeerSpec{
				PublicKey: fooKey.String(),
			},
			out: &mesh.Peer{
				Peer: wireguard.Peer{
					PeerConfig: wgtypes.PeerConfig{
						PublicKey:                   fooKey,
						PersistentKeepaliveInterval: &zero,
					},
				},
			},
		},
		{
			name: "invalid keepalive",
			spec: v1alpha1.PeerSpec{
				PersistentKeepalive: -1,
			},
			out: &mesh.Peer{
				Peer: wireguard.Peer{
					PeerConfig: wgtypes.PeerConfig{
						PersistentKeepaliveInterval: &zero,
					},
				},
			},
		},
		{
			name: "valid keepalive",
			spec: v1alpha1.PeerSpec{
				PersistentKeepalive: 1,
			},
			out: &mesh.Peer{
				Peer: wireguard.Peer{
					PeerConfig: wgtypes.PeerConfig{
						PersistentKeepaliveInterval: &second,
					},
				},
			},
		},
		{
			name: "valid preshared key",
			spec: v1alpha1.PeerSpec{
				PresharedKey: pskKey.String(),
			},
			out: &mesh.Peer{
				Peer: wireguard.Peer{
					PeerConfig: wgtypes.PeerConfig{
						PersistentKeepaliveInterval: &zero,
						PresharedKey:                pskKey,
					},
				},
			},
		},
	} {
		p := &v1alpha1.Peer{}
		p.Spec = tc.spec
		peer := translatePeer(p)
		if diff := pretty.Compare(peer, tc.out); diff != "" {
			t.Errorf("test case %q: got diff: %v", tc.name, diff)
		}
	}
}
