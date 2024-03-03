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

//go:build linux
// +build linux

package mesh

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

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
)

// Mesh is able to create Kilo network meshes.
type Mesh struct {
	Backend
	cleanup             bool
	cleanUpIface        bool
	cni                 bool
	cniPath             string
	enc                 encapsulation.Encapsulator
	externalIP          *net.IPNet
	granularity         Granularity
	hostname            string
	internalIP          *net.IPNet
	ipTables            *iptables.Controller
	kiloIface           int
	kiloIfaceName       string
	local               bool
	port                int
	priv                wgtypes.Key
	privIface           int
	pub                 wgtypes.Key
	resyncPeriod        time.Duration
	iptablesForwardRule bool
	serviceCIDRs        []*net.IPNet
	subnet              *net.IPNet
	table               *route.Table
	wireGuardIP         *net.IPNet

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
func New(backend Backend, enc encapsulation.Encapsulator, granularity Granularity, hostname string, port int, subnet *net.IPNet, local, cni bool, cniPath, iface string, cleanup bool, cleanUpIface bool, createIface bool, mtu uint, resyncPeriod time.Duration, prioritisePrivateAddr, iptablesForwardRule, routeInternalIP bool, serviceCIDRs []*net.IPNet, logger log.Logger, registerer prometheus.Registerer) (*Mesh, error) {
	if err := os.MkdirAll(kiloPath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create directory to store configuration: %v", err)
	}
	privateB, err := os.ReadFile(privateKeyPath)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to read private key file: %v", err)
	}
	privateB = bytes.Trim(privateB, "\n")
	private, err := wgtypes.ParseKey(string(privateB))
	if err != nil {
		level.Warn(logger).Log("msg", "no private key found on disk; generating one now")
		if private, err = wgtypes.GeneratePrivateKey(); err != nil {
			return nil, err
		}
		if err := os.WriteFile(privateKeyPath, []byte(private.String()), 0600); err != nil {
			return nil, fmt.Errorf("failed to write private key to disk: %v", err)
		}
	}
	public := private.PublicKey()
	if err != nil {
		return nil, err
	}
	cniIndex, err := cniDeviceIndex()
	if err != nil {
		return nil, fmt.Errorf("failed to query netlink for CNI device: %v", err)
	}
	var kiloIface int
	if createIface {
		link, err := netlink.LinkByName(iface)
		if err != nil {
			kiloIface, _, err = wireguard.New(iface, mtu)
			if err != nil {
				return nil, fmt.Errorf("failed to create WireGuard interface: %v", err)
			}
		} else {
			kiloIface = link.Attrs().Index
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
	if !routeInternalIP {
		privateIP = nil
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
	var externalIP *net.IPNet
	if prioritisePrivateAddr && privateIP != nil {
		externalIP = privateIP
	} else {
		externalIP = publicIP
	}
	level.Debug(logger).Log("msg", fmt.Sprintf("using %s as the public IP address", publicIP.String()))
	ipTables, err := iptables.New(iptables.WithRegisterer(registerer), iptables.WithLogger(log.With(logger, "component", "iptables")), iptables.WithResyncPeriod(resyncPeriod))
	if err != nil {
		return nil, fmt.Errorf("failed to IP tables controller: %v", err)
	}
	mesh := Mesh{
		Backend:             backend,
		cleanup:             cleanup,
		cleanUpIface:        cleanUpIface,
		cni:                 cni,
		cniPath:             cniPath,
		enc:                 enc,
		externalIP:          externalIP,
		granularity:         granularity,
		hostname:            hostname,
		internalIP:          privateIP,
		ipTables:            ipTables,
		kiloIface:           kiloIface,
		kiloIfaceName:       iface,
		nodes:               make(map[string]*Node),
		peers:               make(map[string]*Peer),
		port:                port,
		priv:                private,
		privIface:           privIface,
		pub:                 public,
		resyncPeriod:        resyncPeriod,
		iptablesForwardRule: iptablesForwardRule,
		local:               local,
		serviceCIDRs:        serviceCIDRs,
		subnet:              subnet,
		table:               route.NewTable(),
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
	}
	registerer.MustRegister(
		mesh.errorCounter,
		mesh.leaderGuage,
		mesh.nodesGuage,
		mesh.peersGuage,
		mesh.reconcileCounter,
	)
	return &mesh, nil
}

// Run starts the mesh.
func (m *Mesh) Run(ctx context.Context) error {
	if err := m.Nodes().Init(ctx); err != nil {
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
	if err := m.Peers().Init(ctx); err != nil {
		return fmt.Errorf("failed to initialize peer backend: %v", err)
	}
	ipTablesErrors, err := m.ipTables.Run(ctx.Done())
	if err != nil {
		return fmt.Errorf("failed to watch for IP tables updates: %v", err)
	}
	routeErrors, err := m.table.Run(ctx.Done())
	if err != nil {
		return fmt.Errorf("failed to watch for route table updates: %v", err)
	}
	go func() {
		for {
			var err error
			select {
			case err = <-ipTablesErrors:
			case err = <-routeErrors:
			case <-ctx.Done():
				return
			}
			if err != nil {
				level.Error(m.logger).Log("error", err)
				m.errorCounter.WithLabelValues("run").Inc()
			}
		}
	}()
	if m.cleanup {
		defer m.cleanUp()
	}
	resync := time.NewTimer(m.resyncPeriod)
	checkIn := time.NewTimer(checkInPeriod)
	nw := m.Nodes().Watch()
	pw := m.Peers().Watch()
	var ne *NodeEvent
	var pe *PeerEvent
	for {
		select {
		case ne = <-nw:
			m.syncNodes(ctx, ne)
		case pe = <-pw:
			m.syncPeers(pe)
		case <-checkIn.C:
			m.checkIn(ctx)
			checkIn.Reset(checkInPeriod)
		case <-resync.C:
			if m.cni {
				m.updateCNIConfig()
			}
			m.applyTopology()
			resync.Reset(m.resyncPeriod)
		case <-ctx.Done():
			return nil
		}
	}
}

func (m *Mesh) syncNodes(ctx context.Context, e *NodeEvent) {
	logger := log.With(m.logger, "event", e.Type)
	level.Debug(logger).Log("msg", "syncing nodes", "event", e.Type)
	if isSelf(m.hostname, e.Node) {
		level.Debug(logger).Log("msg", "processing local node", "node", e.Node)
		m.handleLocal(ctx, e.Node)
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
	key := e.Peer.PublicKey.String()
	if !e.Peer.Ready() {
		// Trace non ready peer with their presence in the mesh.
		_, ok := m.peers[key]
		level.Debug(logger).Log("msg", "received non ready peer", "peer", e.Peer, "in-mesh", ok)
	}
	switch e.Type {
	case AddEvent:
		fallthrough
	case UpdateEvent:
		if e.Old != nil && key != e.Old.PublicKey.String() {
			delete(m.peers, e.Old.PublicKey.String())
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
func (m *Mesh) checkIn(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := m.nodes[m.hostname]
	if n == nil {
		level.Debug(m.logger).Log("msg", "no local node found in backend")
		return
	}
	oldTime := n.LastSeen
	n.LastSeen = time.Now().Unix()
	if err := m.Nodes().Set(ctx, m.hostname, n); err != nil {
		level.Error(m.logger).Log("error", fmt.Sprintf("failed to set local node: %v", err), "node", n)
		m.errorCounter.WithLabelValues("checkin").Inc()
		// Revert time.
		n.LastSeen = oldTime
		return
	}
	level.Debug(m.logger).Log("msg", "successfully checked in local node in backend")
}

func (m *Mesh) handleLocal(ctx context.Context, n *Node) {
	// Allow the IPs to be overridden.
	if !n.Endpoint.Ready() {
		e := wireguard.NewEndpoint(m.externalIP.IP, m.port)
		level.Info(m.logger).Log("msg", "overriding endpoint", "node", m.hostname, "old endpoint", n.Endpoint.String(), "new endpoint", e.String())
		n.Endpoint = e
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
		if err := m.Nodes().Set(ctx, m.hostname, local); err != nil {
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

	wgClient, err := wgctrl.New()
	if err != nil {
		level.Error(m.logger).Log("error", err)
		m.errorCounter.WithLabelValues("apply").Inc()
		return
	}
	defer wgClient.Close()

	// wgDevice is the current configuration of the wg interface.
	wgDevice, err := wgClient.Device(m.kiloIfaceName)
	if err != nil {
		level.Error(m.logger).Log("error", err)
		m.errorCounter.WithLabelValues("apply").Inc()
		return
	}

	natEndpoints := discoverNATEndpoints(nodes, peers, wgDevice, m.logger)
	nodes[m.hostname].DiscoveredEndpoints = natEndpoints
	t, err := NewTopology(nodes, peers, m.granularity, m.hostname, nodes[m.hostname].Endpoint.Port(), m.priv, m.subnet, m.serviceCIDRs, nodes[m.hostname].PersistentKeepalive, m.logger)
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
	ipRules := t.Rules(m.cni, m.iptablesForwardRule)

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

		encIpRules := m.enc.Rules(cidrs)
		ipRules = encIpRules.AppendRuleSet(ipRules)

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
		conf := t.Conf()
		equal, diff := conf.Equal(wgDevice)
		if !equal {
			level.Info(m.logger).Log("msg", "WireGuard configurations are different", "diff", diff)
			level.Debug(m.logger).Log("msg", "changing wg config", "config", conf.WGConfig())
			if err := wgClient.ConfigureDevice(m.kiloIfaceName, conf.WGConfig()); err != nil {
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

func (m *Mesh) cleanUp() {
	if err := m.ipTables.CleanUp(); err != nil {
		level.Error(m.logger).Log("error", fmt.Sprintf("failed to clean up IP tables: %v", err))
		m.errorCounter.WithLabelValues("cleanUp").Inc()
	}
	if err := m.table.CleanUp(); err != nil {
		level.Error(m.logger).Log("error", fmt.Sprintf("failed to clean up routes: %v", err))
		m.errorCounter.WithLabelValues("cleanUp").Inc()
	}
	if m.cleanUpIface {
		if err := iproute.RemoveInterface(m.kiloIface); err != nil {
			level.Error(m.logger).Log("error", fmt.Sprintf("failed to remove WireGuard interface: %v", err))
			m.errorCounter.WithLabelValues("cleanUp").Inc()
		}
	}
	{
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := m.Nodes().CleanUp(ctx, m.hostname); err != nil {
			level.Error(m.logger).Log("error", fmt.Sprintf("failed to clean up node backend: %v", err))
			m.errorCounter.WithLabelValues("cleanUp").Inc()
		}
	}
	{
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := m.Peers().CleanUp(ctx, m.hostname); err != nil {
			level.Error(m.logger).Log("error", fmt.Sprintf("failed to clean up peer backend: %v", err))
			m.errorCounter.WithLabelValues("cleanUp").Inc()
		}
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
		// Resolve the Endpoint
		if _, err := m.nodes[k].Endpoint.UDPAddr(true); err != nil {
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
		if !m.peers[k].Endpoint.Ready() {
			continue
		}
		if _, err := m.peers[k].Endpoint.UDPAddr(true); err != nil {
			return err
		}
	}
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
	return a.Key.String() == b.Key.String() &&
		ipNetsEqual(a.WireGuardIP, b.WireGuardIP) &&
		ipNetsEqual(a.InternalIP, b.InternalIP) &&
		a.Leader == b.Leader &&
		a.Location == b.Location &&
		a.Name == b.Name &&
		subnetsEqual(a.Subnet, b.Subnet) &&
		a.Ready() == b.Ready() &&
		a.PersistentKeepalive == b.PersistentKeepalive &&
		discoveredEndpointsAreEqual(a.DiscoveredEndpoints, b.DiscoveredEndpoints) &&
		ipNetSlicesEqual(a.AllowedLocationIPs, b.AllowedLocationIPs) &&
		a.Granularity == b.Granularity
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
		if !ipNetsEqual(&a.AllowedIPs[i], &b.AllowedIPs[i]) {
			return false
		}
	}
	return a.PublicKey.String() == b.PublicKey.String() &&
		(a.PresharedKey == nil) == (b.PresharedKey == nil) &&
		(a.PresharedKey == nil || a.PresharedKey.String() == b.PresharedKey.String()) &&
		(a.PersistentKeepaliveInterval == nil) == (b.PersistentKeepaliveInterval == nil) &&
		(a.PersistentKeepaliveInterval == nil || *a.PersistentKeepaliveInterval == *b.PersistentKeepaliveInterval)
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

func ipNetSlicesEqual(a, b []net.IPNet) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !ipNetsEqual(&a[i], &b[i]) {
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

func udpAddrsEqual(a, b *net.UDPAddr) bool {
	if a == nil && b == nil {
		return true
	}
	if (a != nil) != (b != nil) {
		return false
	}
	if a.Zone != b.Zone {
		return false
	}
	if a.Port != b.Port {
		return false
	}
	return a.IP.Equal(b.IP)
}

func discoveredEndpointsAreEqual(a, b map[string]*net.UDPAddr) bool {
	if a == nil && b == nil {
		return true
	}
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !udpAddrsEqual(a[k], b[k]) {
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
// Discovered endpionts will never be DNS names, because WireGuard will always resolve them to net.UDPAddr.
func discoverNATEndpoints(nodes map[string]*Node, peers map[string]*Peer, conf *wgtypes.Device, logger log.Logger) map[string]*net.UDPAddr {
	natEndpoints := make(map[string]*net.UDPAddr)
	keys := make(map[string]wgtypes.Peer)
	for i := range conf.Peers {
		keys[conf.Peers[i].PublicKey.String()] = conf.Peers[i]
	}
	for _, n := range nodes {
		if peer, ok := keys[n.Key.String()]; ok && n.PersistentKeepalive != time.Duration(0) {
			level.Debug(logger).Log("msg", "WireGuard Update NAT Endpoint", "node", n.Name, "endpoint", peer.Endpoint, "former-endpoint", n.Endpoint, "same", peer.Endpoint.String() == n.Endpoint.String(), "latest-handshake", peer.LastHandshakeTime)
			// Don't update the endpoint, if there was never any handshake.
			if !peer.LastHandshakeTime.Equal(time.Time{}) {
				natEndpoints[n.Key.String()] = peer.Endpoint
			}
		}
	}
	for _, p := range peers {
		if peer, ok := keys[p.PublicKey.String()]; ok && p.PersistentKeepaliveInterval != nil {
			if !peer.LastHandshakeTime.Equal(time.Time{}) {
				natEndpoints[p.PublicKey.String()] = peer.Endpoint
			}
		}
	}
	level.Debug(logger).Log("msg", "Discovered WireGuard NAT Endpoints", "DiscoveredEndpoints", natEndpoints)
	return natEndpoints
}
