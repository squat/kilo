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
	"time"

	"github.com/squat/kilo/pkg/wireguard"
)

const (
	// checkInPeriod is how often nodes should check-in.
	checkInPeriod = 30 * time.Second
	// DefaultKiloInterface is the default interface created and used by Kilo.
	DefaultKiloInterface = "kilo0"
	// DefaultKiloPort is the default UDP port Kilo uses.
	DefaultKiloPort = 51820
	// DefaultCNIPath is the default path to the CNI config file.
	DefaultCNIPath = "/etc/cni/net.d/10-kilo.conflist"
)

// DefaultKiloSubnet is the default CIDR for Kilo.
var DefaultKiloSubnet = &net.IPNet{IP: []byte{10, 4, 0, 0}, Mask: []byte{255, 255, 0, 0}}

// Granularity represents the abstraction level at which the network
// should be meshed.
type Granularity string

const (
	// LogicalGranularity indicates that the network should create
	// a mesh between logical locations, e.g. data-centers, but not between
	// all nodes within a single location.
	LogicalGranularity Granularity = "location"
	// FullGranularity indicates that the network should create
	// a mesh between every node.
	FullGranularity Granularity = "full"
)

// Node represents a node in the network.
type Node struct {
	Endpoint     *wireguard.Endpoint
	Key          []byte
	NoInternalIP bool
	InternalIP   *net.IPNet
	// LastSeen is a Unix time for the last time
	// the node confirmed it was live.
	LastSeen int64
	// Leader is a suggestion to Kilo that
	// the node wants to lead its segment.
	Leader              bool
	Location            string
	Name                string
	PersistentKeepalive int
	Subnet              *net.IPNet
	WireGuardIP         *net.IPNet
	DiscoveredEndpoints map[string]*wireguard.Endpoint
	AllowedLocationIPs  []*net.IPNet
}

// Ready indicates whether or not the node is ready.
func (n *Node) Ready() bool {
	// Nodes that are not leaders will not have WireGuardIPs, so it is not required.
	return n != nil && n.Endpoint != nil && !(n.Endpoint.IP == nil && n.Endpoint.DNS == "") && n.Endpoint.Port != 0 && n.Key != nil && n.Subnet != nil && time.Now().Unix()-n.LastSeen < int64(checkInPeriod)*2/int64(time.Second)
}

// Peer represents a peer in the network.
type Peer struct {
	wireguard.Peer
	Name string
}

// Ready indicates whether or not the peer is ready.
// Peers can have empty endpoints because they may not have an
// IP, for example if they are behind a NAT, and thus
// will not declare their endpoint and instead allow it to be
// discovered.
func (p *Peer) Ready() bool {
	return p != nil && p.AllowedIPs != nil && len(p.AllowedIPs) != 0 && p.PublicKey != nil
}

// EventType describes what kind of an action an event represents.
type EventType string

const (
	// AddEvent represents an action where an item was added.
	AddEvent EventType = "add"
	// DeleteEvent represents an action where an item was removed.
	DeleteEvent EventType = "delete"
	// UpdateEvent represents an action where an item was updated.
	UpdateEvent EventType = "update"
)

// NodeEvent represents an event concerning a node in the cluster.
type NodeEvent struct {
	Type EventType
	Node *Node
	Old  *Node
}

// PeerEvent represents an event concerning a peer in the cluster.
type PeerEvent struct {
	Type EventType
	Peer *Peer
	Old  *Peer
}

// Backend can create clients for all of the
// primitive types that Kilo deals with, namely:
// * nodes; and
// * peers.
type Backend interface {
	Nodes() NodeBackend
	Peers() PeerBackend
}

// NodeBackend can get nodes by name, init itself,
// list the nodes that should be meshed,
// set Kilo properties for a node,
// clean up any changes applied to the backend,
// and watch for changes to nodes.
type NodeBackend interface {
	CleanUp(string) error
	Get(string) (*Node, error)
	Init(<-chan struct{}) error
	List() ([]*Node, error)
	Set(string, *Node) error
	Watch() <-chan *NodeEvent
}

// PeerBackend can get peers by name, init itself,
// list the peers that should be in the mesh,
// set fields for a peer,
// clean up any changes applied to the backend,
// and watch for changes to peers.
type PeerBackend interface {
	CleanUp(string) error
	Get(string) (*Peer, error)
	Init(<-chan struct{}) error
	List() ([]*Peer, error)
	Set(string, *Peer) error
	Watch() <-chan *PeerEvent
}
