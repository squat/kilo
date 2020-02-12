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

package k8s

import (
	"net"
	"testing"

	"github.com/kylelemons/godebug/pretty"
	v1 "k8s.io/api/core/v1"

	"github.com/squat/kilo/pkg/k8s/apis/kilo/v1alpha1"
	"github.com/squat/kilo/pkg/mesh"
	"github.com/squat/kilo/pkg/wireguard"
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
			out:         &mesh.Node{},
		},
		{
			name: "invalid ips",
			annotations: map[string]string{
				externalIPAnnotationKey: "10.0.0.1",
				internalIPAnnotationKey: "foo",
			},
			out: &mesh.Node{},
		},
		{
			name: "valid ips",
			annotations: map[string]string{
				externalIPAnnotationKey: "10.0.0.1/24",
				internalIPAnnotationKey: "10.0.0.2/32",
			},
			out: &mesh.Node{
				ExternalIP: &net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)},
				InternalIP: &net.IPNet{IP: net.ParseIP("10.0.0.2"), Mask: net.CIDRMask(32, 32)},
			},
		},
		{
			name:        "invalid subnet",
			annotations: map[string]string{},
			out:         &mesh.Node{},
			subnet:      "foo",
		},
		{
			name:        "normalize subnet",
			annotations: map[string]string{},
			out: &mesh.Node{
				Subnet: &net.IPNet{IP: net.ParseIP("10.2.0.0"), Mask: net.CIDRMask(24, 32)},
			},
			subnet: "10.2.0.1/24",
		},
		{
			name:        "valid subnet",
			annotations: map[string]string{},
			out: &mesh.Node{
				Subnet: &net.IPNet{IP: net.ParseIP("10.2.1.0"), Mask: net.CIDRMask(24, 32)},
			},
			subnet: "10.2.1.0/24",
		},
		{
			name: "region",
			labels: map[string]string{
				regionLabelKey: "a",
			},
			out: &mesh.Node{
				Location: "a",
			},
		},
		{
			name: "region override",
			annotations: map[string]string{
				locationAnnotationKey: "b",
			},
			labels: map[string]string{
				regionLabelKey: "a",
			},
			out: &mesh.Node{
				Location: "b",
			},
		},
		{
			name: "external IP override",
			annotations: map[string]string{
				externalIPAnnotationKey:      "10.0.0.1/24",
				forceExternalIPAnnotationKey: "10.0.0.2/24",
			},
			out: &mesh.Node{
				ExternalIP: &net.IPNet{IP: net.ParseIP("10.0.0.2"), Mask: net.CIDRMask(24, 32)},
			},
		},
		{
			name: "wireguard persistent keepalive override",
			annotations: map[string]string{
				persistentKeepAliveKey: "25",
			},
			out: &mesh.Node{
				PersistentKeepAlive: 25,
			},
		},
		{
			name: "internal IP override",
			annotations: map[string]string{
				internalIPAnnotationKey:      "10.1.0.1/24",
				forceInternalIPAnnotationKey: "10.1.0.2/24",
			},
			out: &mesh.Node{
				InternalIP: &net.IPNet{IP: net.ParseIP("10.1.0.2"), Mask: net.CIDRMask(24, 32)},
			},
		},
		{
			name: "invalid time",
			annotations: map[string]string{
				lastSeenAnnotationKey: "foo",
			},
			out: &mesh.Node{},
		},
		{
			name: "complete",
			annotations: map[string]string{
				externalIPAnnotationKey:      "10.0.0.1/24",
				forceExternalIPAnnotationKey: "10.0.0.2/24",
				forceInternalIPAnnotationKey: "10.1.0.2/32",
				internalIPAnnotationKey:      "10.1.0.1/32",
				keyAnnotationKey:             "foo",
				lastSeenAnnotationKey:        "1000000000",
				leaderAnnotationKey:          "",
				locationAnnotationKey:        "b",
				persistentKeepAliveKey:       "25",
				wireGuardIPAnnotationKey:     "10.4.0.1/16",
			},
			labels: map[string]string{
				regionLabelKey: "a",
			},
			out: &mesh.Node{
				ExternalIP:          &net.IPNet{IP: net.ParseIP("10.0.0.2"), Mask: net.CIDRMask(24, 32)},
				InternalIP:          &net.IPNet{IP: net.ParseIP("10.1.0.2"), Mask: net.CIDRMask(32, 32)},
				Key:                 []byte("foo"),
				LastSeen:            1000000000,
				Leader:              true,
				Location:            "b",
				PersistentKeepAlive: 25,
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
		node := translateNode(n)
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
			out:  &mesh.Peer{},
		},
		{
			name: "invalid ips",
			spec: v1alpha1.PeerSpec{
				AllowedIPs: []string{
					"10.0.0.1",
					"foo",
				},
			},
			out: &mesh.Peer{},
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
					AllowedIPs: []*net.IPNet{
						{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)},
						{IP: net.ParseIP("10.0.0.2"), Mask: net.CIDRMask(32, 32)},
					},
				},
			},
		},
		{
			name: "invalid endpoint ip",
			spec: v1alpha1.PeerSpec{
				Endpoint: &v1alpha1.PeerEndpoint{
					IP:   "foo",
					Port: mesh.DefaultKiloPort,
				},
			},
			out: &mesh.Peer{},
		},
		{
			name: "valid endpoint",
			spec: v1alpha1.PeerSpec{
				Endpoint: &v1alpha1.PeerEndpoint{
					IP:   "10.0.0.1",
					Port: mesh.DefaultKiloPort,
				},
			},
			out: &mesh.Peer{
				Peer: wireguard.Peer{
					Endpoint: &wireguard.Endpoint{
						IP:   net.ParseIP("10.0.0.1"),
						Port: mesh.DefaultKiloPort,
					},
				},
			},
		},
		{
			name: "empty key",
			spec: v1alpha1.PeerSpec{
				PublicKey: "",
			},
			out: &mesh.Peer{},
		},
		{
			name: "valid key",
			spec: v1alpha1.PeerSpec{
				PublicKey: "foo",
			},
			out: &mesh.Peer{
				Peer: wireguard.Peer{
					PublicKey: []byte("foo"),
				},
			},
		},
		{
			name: "invalid keepalive",
			spec: v1alpha1.PeerSpec{
				PersistentKeepalive: -1,
			},
			out: &mesh.Peer{},
		},
		{
			name: "valid keepalive",
			spec: v1alpha1.PeerSpec{
				PersistentKeepalive: 1,
			},
			out: &mesh.Peer{
				Peer: wireguard.Peer{
					PersistentKeepalive: 1,
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
