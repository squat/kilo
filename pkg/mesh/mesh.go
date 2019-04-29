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

	"github.com/squat/kilo/pkg/iproute"
	"github.com/squat/kilo/pkg/ipset"
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
)

// Granularity represents the abstraction level at which the network
// should be meshed.
type Granularity string

// Encapsulate identifies what packets within a location should
// be encapsulated.
type Encapsulate string

const (
	// DataCenterGranularity indicates that the network should create
	// a mesh between data-centers but not between nodes within a
	// single data-center.
	DataCenterGranularity Granularity = "data-center"
	// NodeGranularity indicates that the network should create
	// a mesh between every node.
	NodeGranularity Granularity = "node"
	// NeverEncapsulate indicates that no packets within a location
	// should be encapsulated.
	NeverEncapsulate Encapsulate = "never"
	// CrossSubnetEncapsulate indicates that only packets that
	// traverse subnets within a location should be encapsulated.
	CrossSubnetEncapsulate Encapsulate = "crosssubnet"
	// AlwaysEncapsulate indicates that all packets within a location
	// should be encapsulated.
	AlwaysEncapsulate Encapsulate = "always"
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
	Leader   bool
	Location string
	Name     string
	Subnet   *net.IPNet
}

// Ready indicates whether or not the node is ready.
func (n *Node) Ready() bool {
	return n != nil && n.ExternalIP != nil && n.Key != nil && n.InternalIP != nil && n.Subnet != nil && time.Now().Unix()-n.LastSeen < int64(resyncPeriod)*2/int64(time.Second)
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

// Event represents an update event concerning a node in the cluster.
type Event struct {
	Type EventType
	Node *Node
}

// Backend can get nodes by name, init itself,
// list the nodes that should be meshed,
// set Kilo properties for a node,
// clean up any changes applied to the backend,
// and watch for changes to nodes.
type Backend interface {
	CleanUp(string) error
	Get(string) (*Node, error)
	Init(<-chan struct{}) error
	List() ([]*Node, error)
	Set(string, *Node) error
	Watch() <-chan *Event
}

// Mesh is able to create Kilo network meshes.
type Mesh struct {
	Backend
	encapsulate Encapsulate
	externalIP  *net.IPNet
	granularity Granularity
	hostname    string
	internalIP  *net.IPNet
	ipset       *ipset.Set
	ipTables    *iptables.Controller
	kiloIface   int
	key         []byte
	local       bool
	port        int
	priv        []byte
	privIface   int
	pub         []byte
	pubIface    int
	stop        chan struct{}
	subnet      *net.IPNet
	table       *route.Table
	tunlIface   int

	// nodes is a mutable field in the struct
	// and needs to be guarded.
	nodes map[string]*Node
	mu    sync.Mutex

	errorCounter     *prometheus.CounterVec
	nodesGuage       prometheus.Gauge
	reconcileCounter prometheus.Counter
	logger           log.Logger
}

// New returns a new Mesh instance.
func New(backend Backend, encapsulate Encapsulate, granularity Granularity, hostname string, port int, subnet *net.IPNet, local bool, logger log.Logger) (*Mesh, error) {
	if err := os.MkdirAll(KiloPath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create directory to store configuration: %v", err)
	}
	private, err := ioutil.ReadFile(PrivateKeyPath)
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
	privateIP, publicIP, err := getIP(hostname)
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
	kiloIface, err := wireguard.New("kilo")
	if err != nil {
		return nil, fmt.Errorf("failed to create WireGuard interface: %v", err)
	}
	var tunlIface int
	if encapsulate != NeverEncapsulate {
		if tunlIface, err = iproute.NewIPIP(privIface); err != nil {
			return nil, fmt.Errorf("failed to create tunnel interface: %v", err)
		}
		if err := iproute.Set(tunlIface, true); err != nil {
			return nil, fmt.Errorf("failed to set tunnel interface up: %v", err)
		}
	}
	level.Debug(logger).Log("msg", fmt.Sprintf("using %s as the private IP address", privateIP.String()))
	level.Debug(logger).Log("msg", fmt.Sprintf("using %s as the public IP address", publicIP.String()))
	ipTables, err := iptables.New(len(subnet.IP))
	if err != nil {
		return nil, fmt.Errorf("failed to IP tables controller: %v", err)
	}
	return &Mesh{
		Backend:     backend,
		encapsulate: encapsulate,
		externalIP:  publicIP,
		granularity: granularity,
		hostname:    hostname,
		internalIP:  privateIP,
		// This is a patch until Calico supports
		// other hosts adding IPIP iptables rules.
		ipset:     ipset.New("cali40all-hosts-net"),
		ipTables:  ipTables,
		kiloIface: kiloIface,
		nodes:     make(map[string]*Node),
		port:      port,
		priv:      private,
		privIface: privIface,
		pub:       public,
		pubIface:  pubIface,
		local:     local,
		stop:      make(chan struct{}),
		subnet:    subnet,
		table:     route.NewTable(),
		tunlIface: tunlIface,
		errorCounter: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kilo_errors_total",
			Help: "Number of errors that occurred while administering the mesh.",
		}, []string{"event"}),
		nodesGuage: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kilo_nodes",
			Help: "Number of in the mesh.",
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
	if err := m.Init(m.stop); err != nil {
		return fmt.Errorf("failed to initialize backend: %v", err)
	}
	ipsetErrors, err := m.ipset.Run(m.stop)
	if err != nil {
		return fmt.Errorf("failed to watch for ipset updates: %v", err)
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
			case err = <-ipsetErrors:
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
	w := m.Watch()
	for {
		var e *Event
		select {
		case e = <-w:
			m.sync(e)
		case <-t.C:
			m.checkIn()
			m.applyTopology()
			t.Reset(resyncPeriod)
		case <-m.stop:
			return nil
		}
	}
}

func (m *Mesh) sync(e *Event) {
	logger := log.With(m.logger, "event", e.Type)
	level.Debug(logger).Log("msg", "syncing", "event", e.Type)
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
			level.Info(logger).Log("msg", "node is no longer in the mesh", "node", e.Node)
			delete(m.nodes, e.Node.Name)
			diff = true
		}
	} else {
		switch e.Type {
		case AddEvent:
			fallthrough
		case UpdateEvent:
			if !nodesAreEqual(m.nodes[e.Node.Name], e.Node) {
				m.nodes[e.Node.Name] = e.Node
				diff = true
			}
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

// checkIn will try to update the local node's LastSeen timestamp
// in the backend.
func (m *Mesh) checkIn() {
	m.mu.Lock()
	n := m.nodes[m.hostname]
	m.mu.Unlock()
	if n == nil {
		level.Debug(m.logger).Log("msg", "no local node found in backend")
		return
	}
	n.LastSeen = time.Now().Unix()
	if err := m.Set(m.hostname, n); err != nil {
		level.Error(m.logger).Log("error", fmt.Sprintf("failed to set local node: %v", err), "node", n)
		m.errorCounter.WithLabelValues("checkin").Inc()
		return
	}
	level.Debug(m.logger).Log("msg", "successfully checked in local node in backend")
}

func (m *Mesh) handleLocal(n *Node) {
	// Allow the external IP to be overridden.
	if n.ExternalIP == nil {
		n.ExternalIP = m.externalIP
	}
	// Compare the given node to the calculated local node.
	// Take leader, location, and subnet from the argument, as these
	// are not determined by kilo.
	local := &Node{
		ExternalIP: n.ExternalIP,
		Key:        m.pub,
		InternalIP: m.internalIP,
		LastSeen:   time.Now().Unix(),
		Leader:     n.Leader,
		Location:   n.Location,
		Name:       m.hostname,
		Subnet:     n.Subnet,
	}
	if !nodesAreEqual(n, local) {
		level.Debug(m.logger).Log("msg", "local node differs from backend")
		if err := m.Set(m.hostname, local); err != nil {
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
	// Ensure all unready nodes are removed.
	var ready float64
	for n := range m.nodes {
		if !m.nodes[n].Ready() {
			delete(m.nodes, n)
			continue
		}
		ready++
	}
	m.nodesGuage.Set(ready)
	// We cannot do anything with the topology until the local node is available.
	if m.nodes[m.hostname] == nil {
		return
	}
	t, err := NewTopology(m.nodes, m.granularity, m.hostname, m.port, m.priv, m.subnet)
	if err != nil {
		level.Error(m.logger).Log("error", err)
		m.errorCounter.WithLabelValues("apply").Inc()
		return
	}
	conf, err := t.Conf()
	if err != nil {
		level.Error(m.logger).Log("error", err)
		m.errorCounter.WithLabelValues("apply").Inc()
	}
	if err := ioutil.WriteFile(ConfPath, conf, 0600); err != nil {
		level.Error(m.logger).Log("error", err)
		m.errorCounter.WithLabelValues("apply").Inc()
		return
	}
	var private *net.IPNet
	// If we are not encapsulating packets to the local private network,
	// then pass the private IP to add an exception to the NAT rule.
	if m.encapsulate != AlwaysEncapsulate {
		private = t.privateIP
	}
	rules := iptables.MasqueradeRules(private, m.nodes[m.hostname].Subnet, t.RemoteSubnets())
	rules = append(rules, iptables.ForwardRules(m.subnet)...)
	if err := m.ipTables.Set(rules); err != nil {
		level.Error(m.logger).Log("error", err)
		m.errorCounter.WithLabelValues("apply").Inc()
		return
	}
	if m.encapsulate != NeverEncapsulate {
		var peers []net.IP
		for _, s := range t.Segments {
			if s.Location == m.nodes[m.hostname].Location {
				peers = s.privateIPs
				break
			}
		}
		if err := m.ipset.Set(peers); err != nil {
			level.Error(m.logger).Log("error", err)
			m.errorCounter.WithLabelValues("apply").Inc()
			return
		}
		if m.local {
			if err := iproute.SetAddress(m.tunlIface, oneAddressCIDR(newAllocator(*m.nodes[m.hostname].Subnet).next().IP)); err != nil {
				level.Error(m.logger).Log("error", err)
				m.errorCounter.WithLabelValues("apply").Inc()
				return
			}
		}
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
		equal, err := wireguard.CompareConf(conf, oldConf)
		if err != nil {
			level.Error(m.logger).Log("error", err)
			m.errorCounter.WithLabelValues("apply").Inc()
			// Don't return here, simply overwrite the old configuration.
			equal = false
		}
		if !equal {
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
	routes := t.Routes(m.kiloIface, m.privIface, m.tunlIface, m.local, m.encapsulate)
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
	if err := os.Remove(PrivateKeyPath); err != nil {
		level.Error(m.logger).Log("error", fmt.Sprintf("failed to delete private key: %v", err))
		m.errorCounter.WithLabelValues("cleanUp").Inc()
	}
	if err := os.Remove(ConfPath); err != nil {
		level.Error(m.logger).Log("error", fmt.Sprintf("failed to delete configuration file: %v", err))
		m.errorCounter.WithLabelValues("cleanUp").Inc()
	}
	if err := iproute.RemoveInterface(m.kiloIface); err != nil {
		level.Error(m.logger).Log("error", fmt.Sprintf("failed to remove wireguard interface: %v", err))
		m.errorCounter.WithLabelValues("cleanUp").Inc()
	}
	if err := m.CleanUp(m.hostname); err != nil {
		level.Error(m.logger).Log("error", fmt.Sprintf("failed to clean up backend: %v", err))
		m.errorCounter.WithLabelValues("cleanUp").Inc()
	}
	if err := m.ipset.CleanUp(); err != nil {
		level.Error(m.logger).Log("error", fmt.Sprintf("failed to clean up ipset: %v", err))
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
	// Ignore LastSeen when comparing equality.
	return ipNetsEqual(a.ExternalIP, b.ExternalIP) && string(a.Key) == string(b.Key) && ipNetsEqual(a.InternalIP, b.InternalIP) && a.Leader == b.Leader && a.Location == b.Location && a.Name == b.Name && subnetsEqual(a.Subnet, b.Subnet)
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
