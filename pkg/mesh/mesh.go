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

// +build linux

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

const (
	// kiloPath is the directory where Kilo stores its configuration.
	kiloPath = "/var/lib/kilo"
	// privateKeyPath is the filepath where the WireGuard private key is stored.
	privateKeyPath = kiloPath + "/key"
	// confPath is the filepath where the WireGuard configuration is stored.
	confPath = kiloPath + "/conf"
)

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
	resyncPeriod time.Duration
	stop         chan struct{}
	subnet       *net.IPNet
	table        *route.Table
	wireGuardIP  *net.IPNet

	// nodes and peers are mutable fields in the struct
	// and need to be guarded.
	nodes map[string]*Node
	peers map[string]*Peer
	mu    sync.Mutex

	errorCounter     *prometheus.CounterVec
	leaderGuage      prometheus.Gauge
	nodesGuage       prometheus.Gauge
	peersGuage       prometheus.Gauge
	reconcileCounter prometheus.Counter
	logger           log.Logger
}

// New returns a new Mesh instance.
func New(backend Backend, enc encapsulation.Encapsulator, granularity Granularity, hostname string, port uint32, subnet *net.IPNet, local, cni bool, cniPath, iface string, cleanUpIface bool, createIface bool, resyncPeriod time.Duration, logger log.Logger) (*Mesh, error) {
	if err := os.MkdirAll(kiloPath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create directory to store configuration: %v", err)
	}
	private, err := ioutil.ReadFile(privateKeyPath)
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
	if err := ioutil.WriteFile(privateKeyPath, private, 0600); err != nil {
		return nil, fmt.Errorf("failed to write private key to disk: %v", err)
	}
	cniIndex, err := cniDeviceIndex()
	if err != nil {
		return nil, fmt.Errorf("failed to query netlink for CNI device: %v", err)
	}
	var kiloIface int
	if createIface {
		kiloIface, _, err = wireguard.New(iface)
		if err != nil {
			return nil, fmt.Errorf("failed to create WireGuard interface: %v", err)
		}
	} else {
		link, err := netlink.LinkByName(iface)
		if err != nil {
			return nil, fmt.Errorf("failed to get interface index: %v", err)
		}
		kiloIface = link.Attrs().Index
	}
	privateIP, publicIP, err := getIP(hostname, kiloIface, enc.Index(), cniIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to find public IP: %v", err)
	}
	var privIface int
	if privateIP != nil {
		ifaces, err := interfacesForIP(privateIP)
		if err != nil {
			return nil, fmt.Errorf("failed to find interface for private IP: %v", err)
		}
		privIface = ifaces[0].Index
		if enc.Strategy() != encapsulation.Never {
			if err := enc.Init(privIface); err != nil {
				return nil, fmt.Errorf("failed to initialize encapsulator: %v", err)
			}
		}
		level.Debug(logger).Log("msg", fmt.Sprintf("using %s as the private IP address", privateIP.String()))
	} else {
		enc = encapsulation.Noop(enc.Strategy())
		level.Debug(logger).Log("msg", "running without a private IP address")
	}
	level.Debug(logger).Log("msg", fmt.Sprintf("using %s as the public IP address", publicIP.String()))
	ipTables, err := iptables.New(iptables.WithLogger(log.With(logger, "component", "iptables")), iptables.WithResyncPeriod(resyncPeriod))
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
		resyncPeriod: resyncPeriod,
		local:        local,
		stop:         make(chan struct{}),
		subnet:       subnet,
		table:        route.NewTable(),
		errorCounter: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kilo_errors_total",
			Help: "Number of errors that occurred while administering the mesh.",
		}, []string{"event"}),
		leaderGuage: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kilo_leader",
			Help: "Leadership status of the node.",
		}),
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
	if m.cni {
		if n, err := m.Nodes().Get(m.hostname); err == nil {
			m.nodes[m.hostname] = n
			m.updateCNIConfig()
		} else {
			level.Warn(m.logger).Log("error", fmt.Errorf("failed to get node %q: %v", m.hostname, err))
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
	resync := time.NewTimer(m.resyncPeriod)
	checkIn := time.NewTimer(checkInPeriod)
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
		case <-checkIn.C:
			m.checkIn()
			checkIn.Reset(checkInPeriod)
		case <-resync.C:
			if m.cni {
				m.updateCNIConfig()
			}
			m.applyTopology()
			resync.Reset(m.resyncPeriod)
		case <-m.stop:
			return nil
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
		// Trace non ready nodes with their presence in the mesh.
		_, ok := m.nodes[e.Node.Name]
		level.Debug(logger).Log("msg", "received non ready node", "node", e.Node, "in-mesh", ok)
	}
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
		// Trace non ready peer with their presence in the mesh.
		_, ok := m.peers[key]
		level.Debug(logger).Log("msg", "received non ready peer", "peer", e.Peer, "in-mesh", ok)
	}
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
	if n.Endpoint == nil || (n.Endpoint.DNS == "" && n.Endpoint.IP == nil) {
		n.Endpoint = &wireguard.Endpoint{DNSOrIP: wireguard.DNSOrIP{IP: m.externalIP.IP}, Port: m.port}
	}
	if n.InternalIP == nil && !n.NoInternalIP {
		n.InternalIP = m.internalIP
	}
	// Compare the given node to the calculated local node.
	// Take leader, location, and subnet from the argument, as these
	// are not determined by kilo.
	local := &Node{
		Endpoint:            n.Endpoint,
		Key:                 m.pub,
		NoInternalIP:        n.NoInternalIP,
		InternalIP:          n.InternalIP,
		LastSeen:            time.Now().Unix(),
		Leader:              n.Leader,
		Location:            n.Location,
		Name:                m.hostname,
		PersistentKeepalive: n.PersistentKeepalive,
		Subnet:              n.Subnet,
		WireGuardIP:         m.wireGuardIP,
		DiscoveredEndpoints: n.DiscoveredEndpoints,
		AllowedLocationIPs:  n.AllowedLocationIPs,
		Granularity:         m.granularity,
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
	// If we can't resolve an endpoint, then fail and retry later.
	if err := m.resolveEndpoints(); err != nil {
		level.Error(m.logger).Log("error", err)
		m.errorCounter.WithLabelValues("apply").Inc()
		return
	}
	// Ensure only ready nodes are considered.
	nodes := make(map[string]*Node)
	var readyNodes float64
	for k := range m.nodes {
		m.nodes[k].Granularity = m.granularity
		if !m.nodes[k].Ready() {
			continue
		}
		// Make it point to the node without copy.
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
		// Make it point the peer without copy.
		peers[k] = m.peers[k]
		readyPeers++
	}
	m.nodesGuage.Set(readyNodes)
	m.peersGuage.Set(readyPeers)
	// We cannot do anything with the topology until the local node is available.
	if nodes[m.hostname] == nil {
		return
	}
	// Find the Kilo interface name.
	link, err := linkByIndex(m.kiloIface)
	if err != nil {
		level.Error(m.logger).Log("error", err)
		m.errorCounter.WithLabelValues("apply").Inc()
		return
	}
	// Find the old configuration.
	oldConfDump, err := wireguard.ShowDump(link.Attrs().Name)
	if err != nil {
		level.Error(m.logger).Log("error", err)
		m.errorCounter.WithLabelValues("apply").Inc()
		return
	}
	oldConf, err := wireguard.ParseDump(oldConfDump)
	if err != nil {
		level.Error(m.logger).Log("error", err)
		m.errorCounter.WithLabelValues("apply").Inc()
		return
	}
	natEndpoints := discoverNATEndpoints(nodes, peers, oldConf, m.logger)
	nodes[m.hostname].DiscoveredEndpoints = natEndpoints
	t, err := NewTopology(nodes, peers, m.granularity, m.hostname, nodes[m.hostname].Endpoint.Port, m.priv, m.subnet, nodes[m.hostname].PersistentKeepalive, m.logger)
	if err != nil {
		level.Error(m.logger).Log("error", err)
		m.errorCounter.WithLabelValues("apply").Inc()
		return
	}
	// Update the node's WireGuard IP.
	if t.leader {
		m.wireGuardIP = t.wireGuardCIDR
	} else {
		m.wireGuardIP = nil
	}
	conf := t.Conf()
	buf, err := conf.Bytes()
	if err != nil {
		level.Error(m.logger).Log("error", err)
		m.errorCounter.WithLabelValues("apply").Inc()
		return
	}
	if err := ioutil.WriteFile(confPath, buf, 0600); err != nil {
		level.Error(m.logger).Log("error", err)
		m.errorCounter.WithLabelValues("apply").Inc()
		return
	}
	ipRules := t.Rules(m.cni)
	// If we are handling local routes, ensure the local
	// tunnel has an IP address and IPIP traffic is allowed.
	if m.enc.Strategy() != encapsulation.Never && m.local {
		var cidrs []*net.IPNet
		for _, s := range t.segments {
			// If the location prefix is not logicalLocation, but nodeLocation,
			// we don't need to set any extra rules for encapsulation anyways
			// because traffic will go over WireGuard.
			if s.location == logicalLocationPrefix+nodes[m.hostname].Location {
				for i := range s.privateIPs {
					cidrs = append(cidrs, oneAddressCIDR(s.privateIPs[i]))
				}
				break
			}
		}
		ipRules = append(ipRules, m.enc.Rules(cidrs)...)
		// If we are handling local routes, ensure the local
		// tunnel has an IP address.
		if err := m.enc.Set(oneAddressCIDR(newAllocator(*nodes[m.hostname].Subnet).next().IP)); err != nil {
			level.Error(m.logger).Log("error", err)
			m.errorCounter.WithLabelValues("apply").Inc()
			return
		}
	}
	if err := m.ipTables.Set(ipRules); err != nil {
		level.Error(m.logger).Log("error", err)
		m.errorCounter.WithLabelValues("apply").Inc()
		return
	}
	if t.leader {
		m.leaderGuage.Set(1)
		if err := iproute.SetAddress(m.kiloIface, t.wireGuardCIDR); err != nil {
			level.Error(m.logger).Log("error", err)
			m.errorCounter.WithLabelValues("apply").Inc()
			return
		}
		// Setting the WireGuard configuration interrupts existing connections
		// so only set the configuration if it has changed.
		equal := conf.Equal(oldConf)
		if !equal {
			level.Info(m.logger).Log("msg", "WireGuard configurations are different")
			if err := wireguard.SetConf(link.Attrs().Name, confPath); err != nil {
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
		m.leaderGuage.Set(0)
		level.Debug(m.logger).Log("msg", "local node is not the leader")
		if err := iproute.Set(m.kiloIface, false); err != nil {
			level.Error(m.logger).Log("error", err)
			m.errorCounter.WithLabelValues("apply").Inc()
			return
		}
	}
	// We need to add routes last since they may depend
	// on the WireGuard interface.
	routes, rules := t.Routes(link.Attrs().Name, m.kiloIface, m.privIface, m.enc.Index(), m.local, m.enc)
	if err := m.table.Set(routes, rules); err != nil {
		level.Error(m.logger).Log("error", err)
		m.errorCounter.WithLabelValues("apply").Inc()
	}
}

// RegisterMetrics registers Prometheus metrics on the given Prometheus
// registerer.
func (m *Mesh) RegisterMetrics(r prometheus.Registerer) {
	r.MustRegister(
		m.errorCounter,
		m.leaderGuage,
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
	if err := os.Remove(confPath); err != nil {
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

func (m *Mesh) resolveEndpoints() error {
	for k := range m.nodes {
		// Skip unready nodes, since they will not be used
		// in the topology anyways.
		if !m.nodes[k].Ready() {
			continue
		}
		// If the node is ready, then the endpoint is not nil
		// but it may not have a DNS name.
		if m.nodes[k].Endpoint.DNS == "" {
			continue
		}
		if err := resolveEndpoint(m.nodes[k].Endpoint); err != nil {
			return err
		}
	}
	for k := range m.peers {
		// Skip unready peers, since they will not be used
		// in the topology anyways.
		if !m.peers[k].Ready() {
			continue
		}
		// Peers may have nil endpoints.
		if m.peers[k].Endpoint == nil || m.peers[k].Endpoint.DNS == "" {
			continue
		}
		if err := resolveEndpoint(m.peers[k].Endpoint); err != nil {
			return err
		}
	}
	return nil
}

func resolveEndpoint(endpoint *wireguard.Endpoint) error {
	ips, err := net.LookupIP(endpoint.DNS)
	if err != nil {
		return fmt.Errorf("failed to look up DNS name %q: %v", endpoint.DNS, err)
	}
	nets := make([]*net.IPNet, len(ips), len(ips))
	for i := range ips {
		nets[i] = oneAddressCIDR(ips[i])
	}
	sortIPs(nets)
	if len(nets) == 0 {
		return fmt.Errorf("did not find any addresses for DNS name %q", endpoint.DNS)
	}
	endpoint.IP = nets[0].IP
	return nil
}

func isSelf(hostname string, node *Node) bool {
	return node != nil && node.Name == hostname
}

func nodesAreEqual(a, b *Node) bool {
	if (a != nil) != (b != nil) {
		return false
	}
	if a == b {
		return true
	}
	// Check the DNS name first since this package
	// is doing the DNS resolution.
	if !a.Endpoint.Equal(b.Endpoint, true) {
		return false
	}
	// Ignore LastSeen when comparing equality we want to check if the nodes are
	// equivalent. However, we do want to check if LastSeen has transitioned
	// between valid and invalid.
	return string(a.Key) == string(b.Key) && ipNetsEqual(a.WireGuardIP, b.WireGuardIP) && ipNetsEqual(a.InternalIP, b.InternalIP) && a.Leader == b.Leader && a.Location == b.Location && a.Name == b.Name && subnetsEqual(a.Subnet, b.Subnet) && a.Ready() == b.Ready() && a.PersistentKeepalive == b.PersistentKeepalive && discoveredEndpointsAreEqual(a.DiscoveredEndpoints, b.DiscoveredEndpoints) && ipNetSlicesEqual(a.AllowedLocationIPs, b.AllowedLocationIPs) && a.Granularity == b.Granularity
}

func peersAreEqual(a, b *Peer) bool {
	if !(a != nil) == (b != nil) {
		return false
	}
	if a == b {
		return true
	}
	// Check the DNS name first since this package
	// is doing the DNS resolution.
	if !a.Endpoint.Equal(b.Endpoint, true) {
		return false
	}
	if len(a.AllowedIPs) != len(b.AllowedIPs) {
		return false
	}
	for i := range a.AllowedIPs {
		if !ipNetsEqual(a.AllowedIPs[i], b.AllowedIPs[i]) {
			return false
		}
	}
	return string(a.PublicKey) == string(b.PublicKey) && string(a.PresharedKey) == string(b.PresharedKey) && a.PersistentKeepalive == b.PersistentKeepalive
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

func ipNetSlicesEqual(a, b []*net.IPNet) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !ipNetsEqual(a[i], b[i]) {
			return false
		}
	}
	return true
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

func discoveredEndpointsAreEqual(a, b map[string]*wireguard.Endpoint) bool {
	if a == nil && b == nil {
		return true
	}
	if (a != nil) != (b != nil) {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !a[k].Equal(b[k], false) {
			return false
		}
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

// discoverNATEndpoints uses the node's WireGuard configuration to returns a list of the most recently discovered endpoints for all nodes and peers behind NAT so that they can roam.
func discoverNATEndpoints(nodes map[string]*Node, peers map[string]*Peer, conf *wireguard.Conf, logger log.Logger) map[string]*wireguard.Endpoint {
	natEndpoints := make(map[string]*wireguard.Endpoint)
	keys := make(map[string]*wireguard.Peer)
	for i := range conf.Peers {
		keys[string(conf.Peers[i].PublicKey)] = conf.Peers[i]
	}
	for _, n := range nodes {
		if peer, ok := keys[string(n.Key)]; ok && n.PersistentKeepalive > 0 {
			level.Debug(logger).Log("msg", "WireGuard Update NAT Endpoint", "node", n.Name, "endpoint", peer.Endpoint, "former-endpoint", n.Endpoint, "same", n.Endpoint.Equal(peer.Endpoint, false), "latest-handshake", peer.LatestHandshake)
			if (peer.LatestHandshake != time.Time{}) {
				natEndpoints[string(n.Key)] = peer.Endpoint
			}
		}
	}
	for _, p := range peers {
		if peer, ok := keys[string(p.PublicKey)]; ok && p.PersistentKeepalive > 0 {
			if (peer.LatestHandshake != time.Time{}) {
				natEndpoints[string(p.PublicKey)] = peer.Endpoint
			}
		}
	}
	level.Debug(logger).Log("msg", "Discovered WireGuard NAT Endpoints", "DiscoveredEndpoints", natEndpoints)
	return natEndpoints
}
