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

package v1alpha1

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	// Version is the version of this API.
	Version = "v1alpha1"
	// PeerKind is the API kind for the peer resource.
	PeerKind = "Peer"
	// PeerPlural is the plural name for the peer resource.
	PeerPlural = "peers"
)

var (
	// PeerGVK is the GroupVersionKind for Peers.
	PeerGVK = schema.GroupVersionKind{Group: GroupName, Version: Version, Kind: PeerKind}
)

// PeerShortNames are convenient shortnames for the peer resource.
var PeerShortNames = []string{"peer"}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=true

// Peer is a WireGuard peer that should have access to the VPN.
type Peer struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object’s metadata. More info:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/api-conventions.md#metadata
	// +k8s:openapi-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Specification of the desired behavior of the Kilo Peer. More info:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/api-conventions.md#spec-and-status
	Spec PeerSpec `json:"spec"`
}

// PeerSpec is the description and configuration of a peer.
// +k8s:openapi-gen=true
type PeerSpec struct {
	// AllowedIPs is the list of IP addresses that are allowed
	// for the given peer's tunnel.
	AllowedIPs []string `json:"allowedIPs"`
	// Endpoint is the initial endpoint for connections to the peer.
	// +optional
	Endpoint *PeerEndpoint `json:"endpoint,omitempty"`
	// PersistentKeepalive is the interval in seconds of the emission
	// of keepalive packets by the peer. This defaults to 0, which
	// disables the feature.
	// +optional
	PersistentKeepalive int `json:"persistentKeepalive,omitempty"`
	// PresharedKey is the optional symmetric encryption key for the peer.
	// +optional
	PresharedKey string `json:"presharedKey"`
	// PublicKey is the WireGuard public key for the peer.
	PublicKey string `json:"publicKey"`
}

// PeerEndpoint represents a WireGuard enpoint, which is a ip:port tuple.
type PeerEndpoint struct {
	// DNSOrIP is a DNS name or an IP address.
	DNSOrIP `json:"dnsOrIP"`
	// Port must be a valid port number.
	Port uint32 `json:"port"`
}

// DNSOrIP represents either a DNS name or an IP address.
// IPs, as they are more specific, are preferred.
type DNSOrIP struct {
	// DNS must be a valid RFC 1123 subdomain.
	// +optional
	DNS string `json:"dns,omitempty"`
	// IP must be a valid IP address.
	// +optional
	IP string `json:"ip,omitempty"`
}

// PeerName is the peer resource's FQDN.
var PeerName = PeerPlural + "." + GroupName

// AsOwner creates a new owner reference for the peer to apply to dependent resource.
func (p *Peer) AsOwner() metav1.OwnerReference {
	trueVar := true
	return metav1.OwnerReference{
		APIVersion:         p.APIVersion,
		Kind:               p.Kind,
		Name:               p.Name,
		UID:                p.UID,
		BlockOwnerDeletion: &trueVar,
		Controller:         &trueVar,
	}
}

// Copy creates a deep copy of the peer.
func (p *Peer) Copy() *Peer {
	new := Peer{}
	b, err := json.Marshal(*p)
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(b, &new)
	if err != nil {
		panic(err)
	}
	return &new
}

// Validate ensures that all the fields of a peer's spec are valid.
func (p *Peer) Validate() error {
	for _, ip := range p.Spec.AllowedIPs {
		if _, n, err := net.ParseCIDR(ip); err != nil {
			return fmt.Errorf("failed to parse %q as a valid IP address: %w", ip, err)
		} else if n == nil {
			return fmt.Errorf("got invalid IP address for %q", ip)
		}
	}
	if p.Spec.Endpoint != nil {
		if p.Spec.Endpoint.IP == "" && p.Spec.Endpoint.DNS == "" {
			return errors.New("either an endpoint DNS name IP address must be given")
		}
		if p.Spec.Endpoint.DNS != "" {
			if errs := validation.IsDNS1123Subdomain(p.Spec.Endpoint.DNS); len(errs) != 0 {
				return errors.New(strings.Join(errs, "; "))
			}
		}
		if p.Spec.Endpoint.IP != "" && net.ParseIP(p.Spec.Endpoint.IP) == nil {
			return fmt.Errorf("failed to parse %q as a valid IP address", p.Spec.Endpoint.IP)
		}
		if 1 > p.Spec.Endpoint.Port || p.Spec.Endpoint.Port > 65535 {
			return fmt.Errorf("port must be a valid UDP port number, got %d", p.Spec.Endpoint.Port)
		}
	}
	if p.Spec.PersistentKeepalive < 0 {
		return fmt.Errorf("persistent keepalive must be greater than or equal to zero; got %q", p.Spec.PersistentKeepalive)
	}
	if b, err := base64.StdEncoding.DecodeString(p.Spec.PublicKey); err != nil {
		return fmt.Errorf("WireGuard public key is not base64 encoded: %w", err)
		// Since WireGuard is using Curve25519 for the key exchange, the key length of 256 bits should not change in the near future.
	} else if len(b) != 32 {
		return errors.New("WireGuard public key has invalid length")
	}
	return nil
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// PeerList is a list of peers.
type PeerList struct {
	metav1.TypeMeta `json:",inline"`
	// Standard list metadata.
	// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`
	// List of peers.
	// More info: https://git.k8s.io/community/contributors/devel/api-conventions.md
	Items []Peer `json:"items"`
}
