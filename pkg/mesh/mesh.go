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
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"sync"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netlink"

	"github.com/squat/kilo/pkg/encapsulation"
	"github.com/squat/kilo/pkg/iproute"
	"github.com/squat/kilo/pkg/iptables"
	"github.com/squat/kilo/pkg/route"
	"github.com/squat/kilo/pkg/wireguard"
)

const resyncPeriod = 30 * time.Second

const (
	// KiloPath is the directory where Kilo stores its configuration.
	KiloPath = "/var/lib/kilo"
	// PrivateKeyPath is the filepath where the WireGuard private key is stored.
	PrivateKeyPath = KiloPath + "/key"
	// ConfPath is the filepath where the WireGuard configuration is stored.
	ConfPath = KiloPath + "/conf"
	// DefaultKiloInterface is the default iterface created and used by Kilo.
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
	ExternalIP *net.IPNet
	Key        []byte
	InternalIP *net.IPNet
	// LastSeen is a Unix time for the last time
	// the node confirmed it was live.
	LastSeen int64
	// Leader is a suggestion to Kilo that
	// the node wants to lead its segment.
	Leader              bool
	Location            string
	Name                string
	PersistentKeepAlive int
	Subnet              *net.IPNet
	WireGuardIP         *net.IPNet
}

// Ready indicates whether or not the node is ready.
func (n *Node) Ready() bool {
	// Nodes that are not leaders will not have WireGuardIPs, so it is not required.
	return n != nil && n.ExternalIP != nil && n.Key != nil && n.InternalIP != nil && n.Subnet != nil && time.Now().Unix()-n.LastSeen < int64(resyncPeriod)*2/int64(time.Second)
}

// Peer represents a peer in the network.
type Peer struct {
	wireguard.Peer
	Name string
}

// Ready indicates whether or not the peer is ready.
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

// Mesh is able to create Kilo network meshes.
type Mesh struct {
	Backend
	cleanUpIface bool
	cni          bool
	cniPath      string
	enc          encapsulation.Encapsulator
	externalIP   *net.IPNet
	granularity  Granularity
	hostname     string
	internalIP   *net.IPNet
	ipTables     *iptables.Controller
	kiloIface    int
	key          []byte
	local        bool
	port         uint32
	priv         []byte
	privIface    int
	pub          []byte
	pubIface     int
	stop         chan struct{}
	subnet       *net.IPNet
	table        *route.Table
	wireGuardIP  *net.IPNet

	// nodes and peers are mutable fields in the struct
	// and needs to be guarded.
	nodes map[string]*Node
	peers map[string]*Peer
	mu    sync.Mutex

	errorCounter     *prometheus.CounterVec
	nodesGuage       prometheus.Gauge
	peersGuage       prometheus.Gauge
	reconcileCounter prometheus.Counter
	logger           log.Logger
}

// New returns a new Mesh instance.
func New(backend Backend, enc encapsulation.Encapsulator, granularity Granularity, hostname string, port uint32, subnet *net.IPNet, local, cni bool, cniPath, iface string, cleanUpIface bool, logger log.Logger) (*Mesh, error) {
	if err := os.MkdirAll(KiloPath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create directory to store configuration: %v", err)
	}
	private, err := ioutil.ReadFile(PrivateKeyPath)
	private = bytes.Trim(private, "\n")
	if err != nil {
		level.Warn(logger).Log("msg", "no private key found on disk; generating one now")
		if private, err = wireguard.GenKey(); err != nil {
			return nil, err
		}
	}
	public, err := wireguard.PubKey(private)
	if err != nil {
		return nil, err
	}
	if err := ioutil.WriteFile(PrivateKeyPath, private, 0600); err != nil {
		return nil, fmt.Errorf("failed to write private key to disk: %v", err)
	}
	cniIndex, err := cniDeviceIndex()
	if err != nil {
		return nil, fmt.Errorf("failed to query netlink for CNI device: %v", err)
	}
	privateIP, publicIP, err := getIP(hostname, enc.Index(), cniIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to find public IP: %v", err)
	}
	ifaces, err := interfacesForIP(privateIP)
	if err != nil {
		return nil, fmt.Errorf("failed to find interface for private IP: %v", err)
	}
	privIface := ifaces[0].Index
	ifaces, err = interfacesForIP(publicIP)
	if err != nil {
		return nil, fmt.Errorf("failed to find interface for public IP: %v", err)
	}
	pubIface := ifaces[0].Index
	kiloIface, _, err := wireguard.New(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to create WireGuard interface: %v", err)
	}
	if enc.Strategy() != encapsulation.Never {
		if err := enc.Init(privIface); err != nil {
			return nil, fmt.Errorf("failed to initialize encapsulator: %v", err)
		}
	}
	level.Debug(logger).Log("msg", fmt.Sprintf("using %s as the private IP address", privateIP.String()))
	level.Debug(logger).Log("msg", fmt.Sprintf("using %s as the public IP address", publicIP.String()))
	ipTables, err := iptables.New(len(subnet.IP))
	if err != nil {
		return nil, fmt.Errorf("failed to IP tables controller: %v", err)
	}
	return &Mesh{
		Backend:      backend,
		cleanUpIface: cleanUpIface,
		cni:          cni,
		cniPath:      cniPath,
		enc:          enc,
		externalIP:   publicIP,
		granularity:  granularity,
		hostname:     hostname,
		internalIP:   privateIP,
		ipTables:     ipTables,
		kiloIface:    kiloIface,
		nodes:        make(map[string]*Node),
		peers:        make(map[string]*Peer),
		port:         port,
		priv:         private,
		privIface:    privIface,
		pub:          public,
		pubIface:     pubIface,
		local:        local,
		stop:         make(chan struct{}),
		subnet:       subnet,
		table:        route.NewTable(),
		errorCounter: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kilo_errors_total",
			Help: "Number of errors that occurred while administering the mesh.",
		}, []string{"event"}),
		nodesGuage: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kilo_nodes",
			Help: "Number of nodes in the mesh.",
		}),
		peersGuage: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kilo_peers",
			Help: "Number of peers in the mesh.",
		}),
		reconcileCounter: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "kilo_reconciles_total",
			Help: "Number of reconciliation attempts.",
		}),
		logger: logger,
	}, nil
}

// Run starts the mesh.
func (m *Mesh) Run() error {
	if err := m.Nodes().Init(m.stop); err != nil {
		return fmt.Errorf("failed to initialize node backend: %v", err)
	}
	// Try to set the CNI config quickly.
	if n, err := m.Nodes().Get(m.hostname); err == nil {
		if n != nil && n.Subnet != nil {
			m.nodes[m.hostname] = n
			m.updateCNIConfig()
		}
	}
	if err := m.Peers().Init(m.stop); err != nil {
		return fmt.Errorf("failed to initialize peer backend: %v", err)
	}
	ipTablesErrors, err := m.ipTables.Run(m.stop)
	if err != nil {
		return fmt.Errorf("failed to watch for IP tables updates: %v", err)
	}
	routeErrors, err := m.table.Run(m.stop)
	if err != nil {
		return fmt.Errorf("failed to watch for route table updates: %v", err)
	}
	go func() {
		for {
			var err error
			select {
			case err = <-ipTablesErrors:
			case err = <-routeErrors:
			case <-m.stop:
				return
			}
			if err != nil {
				level.Error(m.logger).Log("error", err)
				m.errorCounter.WithLabelValues("run").Inc()
			}
		}
	}()
	defer m.cleanUp()
	t := time.NewTimer(resyncPeriod)
	nw := m.Nodes().Watch()
	pw := m.Peers().Watch()
	var ne *NodeEvent
	var pe *PeerEvent
	for {
		select {
		case ne = <-nw:
			m.syncNodes(ne)
		case pe = <-pw:
			m.syncPeers(pe)
		case <-t.C:
			m.checkIn()
			if m.cni {
				m.updateCNIConfig()
			}
			m.syncEndpoints()
			m.applyTopology()
			t.Reset(resyncPeriod)
		case <-m.stop:
			return nil
		}
	}
}

// WireGuard updates the endpoints of peers to match the
// last place a valid packet was received from.
// Periodically we need to syncronize the endpoints
// of peers in the backend to match the WireGuard configuration.
func (m *Mesh) syncEndpoints() {
	link, err := linkByIndex(m.kiloIface)
	if err != nil {
		level.Error(m.logger).Log("error", err)
		m.errorCounter.WithLabelValues("endpoints").Inc()
		return
	}
	conf, err := wireguard.ShowConf(link.Attrs().Name)
	if err != nil {
		level.Error(m.logger).Log("error", err)
		m.errorCounter.WithLabelValues("endpoints").Inc()
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c := wireguard.Parse(conf)
	var key string
	var tmp *Peer
	for i := range c.Peers {
		// Peers are indexed by public key.
		key = string(c.Peers[i].PublicKey)
		if p, ok := m.peers[key]; ok {
			tmp = &Peer{
				Name: p.Name,
				Peer: *c.Peers[i],
			}
			if !peersAreEqual(tmp, p) {
				p.Endpoint = tmp.Endpoint
				if err := m.Peers().Set(p.Name, p); err != nil {
					level.Error(m.logger).Log("error", err)
					m.errorCounter.WithLabelValues("endpoints").Inc()
				}
			}
		}
	}
}

func (m *Mesh) syncNodes(e *NodeEvent) {
	logger := log.With(m.logger, "event", e.Type)
	level.Debug(logger).Log("msg", "syncing nodes", "event", e.Type)
	if isSelf(m.hostname, e.Node) {
		level.Debug(logger).Log("msg", "processing local node", "node", e.Node)
		m.handleLocal(e.Node)
		return
	}
	var diff bool
	m.mu.Lock()
	if !e.Node.Ready() {
		level.Debug(logger).Log("msg", "received incomplete node", "node", e.Node)
		// An existing node is no longer valid
		// so remove it from the mesh.
		if _, ok := m.nodes[e.Node.Name]; ok {
			level.Info(logger).Log("msg", "node is no longer ready", "node", e.Node)
			diff = true
		}
	} else {
		switch e.Type {
		case AddEvent:
			fallthrough
		case UpdateEvent:
			if !nodesAreEqual(m.nodes[e.Node.Name], e.Node) {
				diff = true
			}
			// Even if the nodes are the same,
			// overwrite the old node to update the timestamp.
			m.nodes[e.Node.Name] = e.Node
		case DeleteEvent:
			delete(m.nodes, e.Node.Name)
			diff = true
		}
	}
	m.mu.Unlock()
	if diff {
		level.Info(logger).Log("node", e.Node)
		m.applyTopology()
	}
}

func (m *Mesh) syncPeers(e *PeerEvent) {
	logger := log.With(m.logger, "event", e.Type)
	level.Debug(logger).Log("msg", "syncing peers", "event", e.Type)
	var diff bool
	m.mu.Lock()
	// Peers are indexed by public key.
	key := string(e.Peer.PublicKey)
	if !e.Peer.Ready() {
		level.Debug(logger).Log("msg", "received incomplete peer", "peer", e.Peer)
		// An existing peer is no longer valid
		// so remove it from the mesh.
		if _, ok := m.peers[key]; ok {
			level.Info(logger).Log("msg", "peer is no longer ready", "peer", e.Peer)
			diff = true
		}
	} else {
		switch e.Type {
		case AddEvent:
			fallthrough
		case UpdateEvent:
			if e.Old != nil && key != string(e.Old.PublicKey) {
				delete(m.peers, string(e.Old.PublicKey))
				diff = true
			}
			if !peersAreEqual(m.peers[key], e.Peer) {
				m.peers[key] = e.Peer
				diff = true
			}
		case DeleteEvent:
			delete(m.peers, key)
			diff = true
		}
	}
	m.mu.Unlock()
	if diff {
		level.Info(logger).Log("peer", e.Peer)
		m.applyTopology()
	}
}

// checkIn will try to update the local node's LastSeen timestamp
// in the backend.
func (m *Mesh) checkIn() {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := m.nodes[m.hostname]
	if n == nil {
		level.Debug(m.logger).Log("msg", "no local node found in backend")
		return
	}
	oldTime := n.LastSeen
	n.LastSeen = time.Now().Unix()
	if err := m.Nodes().Set(m.hostname, n); err != nil {
		level.Error(m.logger).Log("error", fmt.Sprintf("failed to set local node: %v", err), "node", n)
		m.errorCounter.WithLabelValues("checkin").Inc()
		// Revert time.
		n.LastSeen = oldTime
		return
	}
	level.Debug(m.logger).Log("msg", "successfully checked in local node in backend")
}

func (m *Mesh) handleLocal(n *Node) {
	// Allow the IPs to be overridden.
	if n.ExternalIP == nil {
		n.ExternalIP = m.externalIP
	}
	if n.InternalIP == nil {
		n.InternalIP = m.internalIP
	}
	// Compare the given node to the calculated local node.
	// Take leader, location, and subnet from the argument, as these
	// are not determined by kilo.
	local := &Node{
		ExternalIP:  n.ExternalIP,
		Key:         m.pub,
		InternalIP:  n.InternalIP,
		LastSeen:    time.Now().Unix(),
		Leader:      n.Leader,
		Location:    n.Location,
		Name:        m.hostname,
		Subnet:      n.Subnet,
		WireGuardIP: m.wireGuardIP,
	}
	if !nodesAreEqual(n, local) {
		level.Debug(m.logger).Log("msg", "local node differs from backend")
		if err := m.Nodes().Set(m.hostname, local); err != nil {
			level.Error(m.logger).Log("error", fmt.Sprintf("failed to set local node: %v", err), "node", local)
			m.errorCounter.WithLabelValues("local").Inc()
			return
		}
		level.Debug(m.logger).Log("msg", "successfully reconciled local node against backend")
	}
	m.mu.Lock()

	n = m.nodes[m.hostname]
	if n == nil {
		n = &Node{}
	}
	m.mu.Unlock()
	if !nodesAreEqual(n, local) {
		m.mu.Lock()
		m.nodes[local.Name] = local
		m.mu.Unlock()
		m.applyTopology()
	}
}

func (m *Mesh) applyTopology() {
	m.reconcileCounter.Inc()
	m.mu.Lock()
	defer m.mu.Unlock()
	// Ensure only ready nodes are considered.
	nodes := make(map[string]*Node)
	var readyNodes float64
	for k := range m.nodes {
		if !m.nodes[k].Ready() {
			continue
		}
		nodes[k] = m.nodes[k]
		readyNodes++
	}
	// Ensure only ready nodes are considered.
	peers := make(map[string]*Peer)
	var readyPeers float64
	for k := range m.peers {
		if !m.peers[k].Ready() {
			continue
		}
		peers[k] = m.peers[k]
		readyPeers++
	}
	m.nodesGuage.Set(readyNodes)
	m.peersGuage.Set(readyPeers)
	// We cannot do anything with the topology until the local node is available.
	if nodes[m.hostname] == nil {
		return
	}
	t, err := NewTopology(nodes, peers, m.granularity, m.hostname, m.port, m.priv, m.subnet)
	if err != nil {
		level.Error(m.logger).Log("error", err)
		m.errorCounter.WithLabelValues("apply").Inc()
		return
	}
	// Update the node's WireGuard IP.
	m.wireGuardIP = t.wireGuardCIDR
	conf := t.Conf()
	buf, err := conf.Bytes()
	if err != nil {
		level.Error(m.logger).Log("error", err)
		m.errorCounter.WithLabelValues("apply").Inc()
	}
	if err := ioutil.WriteFile(ConfPath, buf, 0600); err != nil {
		level.Error(m.logger).Log("error", err)
		m.errorCounter.WithLabelValues("apply").Inc()
		return
	}
	rules := iptables.ForwardRules(m.subnet)
	var peerCIDRs []*net.IPNet
	for _, p := range peers {
		rules = append(rules, iptables.ForwardRules(p.AllowedIPs...)...)
		peerCIDRs = append(peerCIDRs, p.AllowedIPs...)
	}
	rules = append(rules, iptables.MasqueradeRules(m.subnet, oneAddressCIDR(t.privateIP.IP), nodes[m.hostname].Subnet, t.RemoteSubnets(), peerCIDRs)...)
	// If we are handling local routes, ensure the local
	// tunnel has an IP address and IPIP traffic is allowed.
	if m.enc.Strategy() != encapsulation.Never && m.local {
		var cidrs []*net.IPNet
		for _, s := range t.segments {
			if s.location == nodes[m.hostname].Location {
				for i := range s.privateIPs {
					cidrs = append(cidrs, oneAddressCIDR(s.privateIPs[i]))
				}
				break
			}
		}
		rules = append(rules, m.enc.Rules(cidrs)...)

		// If we are handling local routes, ensure the local
		// tunnel has an IP address.
		if err := m.enc.Set(oneAddressCIDR(newAllocator(*nodes[m.hostname].Subnet).next().IP)); err != nil {
			level.Error(m.logger).Log("error", err)
			m.errorCounter.WithLabelValues("apply").Inc()
			return
		}
	}
	if err := m.ipTables.Set(rules); err != nil {
		level.Error(m.logger).Log("error", err)
		m.errorCounter.WithLabelValues("apply").Inc()
		return
	}
	if t.leader {
		if err := iproute.SetAddress(m.kiloIface, t.wireGuardCIDR); err != nil {
			level.Error(m.logger).Log("error", err)
			m.errorCounter.WithLabelValues("apply").Inc()
			return
		}
		link, err := linkByIndex(m.kiloIface)
		if err != nil {
			level.Error(m.logger).Log("error", err)
			m.errorCounter.WithLabelValues("apply").Inc()
			return
		}
		oldConf, err := wireguard.ShowConf(link.Attrs().Name)
		if err != nil {
			level.Error(m.logger).Log("error", err)
			m.errorCounter.WithLabelValues("apply").Inc()
			return
		}
		// Setting the WireGuard configuration interrupts existing connections
		// so only set the configuration if it has changed.
		equal := conf.Equal(wireguard.Parse(oldConf))
		if !equal {
			level.Info(m.logger).Log("msg", "WireGuard configurations are different")
			if err := wireguard.SetConf(link.Attrs().Name, ConfPath); err != nil {
				level.Error(m.logger).Log("error", err)
				m.errorCounter.WithLabelValues("apply").Inc()
				return
			}
		}
		if err := iproute.Set(m.kiloIface, true); err != nil {
			level.Error(m.logger).Log("error", err)
			m.errorCounter.WithLabelValues("apply").Inc()
			return
		}
	} else {
		level.Debug(m.logger).Log("msg", "local node is not the leader")
		if err := iproute.Set(m.kiloIface, false); err != nil {
			level.Error(m.logger).Log("error", err)
			m.errorCounter.WithLabelValues("apply").Inc()
			return
		}
	}
	// We need to add routes last since they may depend
	// on the WireGuard interface.
	routes := t.Routes(m.kiloIface, m.privIface, m.enc.Index(), m.local, m.enc)
	if err := m.table.Set(routes); err != nil {
		level.Error(m.logger).Log("error", err)
		m.errorCounter.WithLabelValues("apply").Inc()
	}
}

// RegisterMetrics registers Prometheus metrics on the given Prometheus
// registerer.
func (m *Mesh) RegisterMetrics(r prometheus.Registerer) {
	r.MustRegister(
		m.errorCounter,
		m.nodesGuage,
		m.peersGuage,
		m.reconcileCounter,
	)
}

// Stop stops the mesh.
func (m *Mesh) Stop() {
	close(m.stop)
}

func (m *Mesh) cleanUp() {
	if err := m.ipTables.CleanUp(); err != nil {
		level.Error(m.logger).Log("error", fmt.Sprintf("failed to clean up IP tables: %v", err))
		m.errorCounter.WithLabelValues("cleanUp").Inc()
	}
	if err := m.table.CleanUp(); err != nil {
		level.Error(m.logger).Log("error", fmt.Sprintf("failed to clean up routes: %v", err))
		m.errorCounter.WithLabelValues("cleanUp").Inc()
	}
	if err := os.Remove(ConfPath); err != nil {
		level.Error(m.logger).Log("error", fmt.Sprintf("failed to delete configuration file: %v", err))
		m.errorCounter.WithLabelValues("cleanUp").Inc()
	}
	if m.cleanUpIface {
		if err := iproute.RemoveInterface(m.kiloIface); err != nil {
			level.Error(m.logger).Log("error", fmt.Sprintf("failed to remove WireGuard interface: %v", err))
			m.errorCounter.WithLabelValues("cleanUp").Inc()
		}
	}
	if err := m.Nodes().CleanUp(m.hostname); err != nil {
		level.Error(m.logger).Log("error", fmt.Sprintf("failed to clean up node backend: %v", err))
		m.errorCounter.WithLabelValues("cleanUp").Inc()
	}
	if err := m.Peers().CleanUp(m.hostname); err != nil {
		level.Error(m.logger).Log("error", fmt.Sprintf("failed to clean up peer backend: %v", err))
		m.errorCounter.WithLabelValues("cleanUp").Inc()
	}
	if err := m.enc.CleanUp(); err != nil {
		level.Error(m.logger).Log("error", fmt.Sprintf("failed to clean up encapsulator: %v", err))
		m.errorCounter.WithLabelValues("cleanUp").Inc()
	}
}

func isSelf(hostname string, node *Node) bool {
	return node != nil && node.Name == hostname
}

func nodesAreEqual(a, b *Node) bool {
	if !(a != nil) == (b != nil) {
		return false
	}
	if a == b {
		return true
	}
	// Ignore LastSeen when comparing equality we want to check if the nodes are
	// equivalent. However, we do want to check if LastSeen has transitioned
	// between valid and invalid.
	return ipNetsEqual(a.ExternalIP, b.ExternalIP) && string(a.Key) == string(b.Key) && ipNetsEqual(a.WireGuardIP, b.WireGuardIP) && ipNetsEqual(a.InternalIP, b.InternalIP) && a.Leader == b.Leader && a.Location == b.Location && a.Name == b.Name && subnetsEqual(a.Subnet, b.Subnet) && a.Ready() == b.Ready()
}

func peersAreEqual(a, b *Peer) bool {
	if !(a != nil) == (b != nil) {
		return false
	}
	if a == b {
		return true
	}
	if !(a.Endpoint != nil) == (b.Endpoint != nil) {
		return false
	}
	if a.Endpoint != nil {
		if !a.Endpoint.IP.Equal(b.Endpoint.IP) || a.Endpoint.Port != b.Endpoint.Port {
			return false
		}
	}
	if len(a.AllowedIPs) != len(b.AllowedIPs) {
		return false
	}
	for i := range a.AllowedIPs {
		if !ipNetsEqual(a.AllowedIPs[i], b.AllowedIPs[i]) {
			return false
		}
	}
	return string(a.PublicKey) == string(b.PublicKey) && a.PersistentKeepalive == b.PersistentKeepalive
}

func ipNetsEqual(a, b *net.IPNet) bool {
	if a == nil && b == nil {
		return true
	}
	if (a != nil) != (b != nil) {
		return false
	}
	if a.Mask.String() != b.Mask.String() {
		return false
	}
	return a.IP.Equal(b.IP)
}

func subnetsEqual(a, b *net.IPNet) bool {
	if a == nil && b == nil {
		return true
	}
	if (a != nil) != (b != nil) {
		return false
	}
	if a.Mask.String() != b.Mask.String() {
		return false
	}
	if !a.Contains(b.IP) {
		return false
	}
	if !b.Contains(a.IP) {
		return false
	}
	return true
}

func linkByIndex(index int) (netlink.Link, error) {
	link, err := netlink.LinkByIndex(index)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface: %v", err)
	}
	return link, nil
}
