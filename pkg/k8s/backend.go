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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path"
	"strconv"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"k8s.io/apimachinery/pkg/util/validation"
	v1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	v1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/squat/kilo/pkg/k8s/apis/kilo/v1alpha1"
	kiloclient "github.com/squat/kilo/pkg/k8s/clientset/versioned"
	v1alpha1informers "github.com/squat/kilo/pkg/k8s/informers/kilo/v1alpha1"
	v1alpha1listers "github.com/squat/kilo/pkg/k8s/listers/kilo/v1alpha1"
	"github.com/squat/kilo/pkg/mesh"
	"github.com/squat/kilo/pkg/wireguard"
)

const (
	// Backend is the name of this mesh backend.
	Backend                      = "kubernetes"
	endpointAnnotationKey        = "kilo.squat.ai/endpoint"
	forceEndpointAnnotationKey   = "kilo.squat.ai/force-endpoint"
	forceInternalIPAnnotationKey = "kilo.squat.ai/force-internal-ip"
	internalIPAnnotationKey      = "kilo.squat.ai/internal-ip"
	keyAnnotationKey             = "kilo.squat.ai/key"
	lastSeenAnnotationKey        = "kilo.squat.ai/last-seen"
	leaderAnnotationKey          = "kilo.squat.ai/leader"
	locationAnnotationKey        = "kilo.squat.ai/location"
	persistentKeepaliveKey       = "kilo.squat.ai/persistent-keepalive"
	wireGuardIPAnnotationKey     = "kilo.squat.ai/wireguard-ip"
	discoveredEndpointsKey       = "kilo.squat.ai/discovered-endpoints"
	// RegionLabelKey is the key for the well-known Kubernetes topology region label.
	RegionLabelKey  = "topology.kubernetes.io/region"
	jsonPatchSlash  = "~1"
	jsonRemovePatch = `{"op": "remove", "path": "%s"}`
)

type backend struct {
	nodes *nodeBackend
	peers *peerBackend
}

// Nodes implements the mesh.Backend interface.
func (b *backend) Nodes() mesh.NodeBackend {
	return b.nodes
}

// Peers implements the mesh.Backend interface.
func (b *backend) Peers() mesh.PeerBackend {
	return b.peers
}

type nodeBackend struct {
	client        kubernetes.Interface
	events        chan *mesh.NodeEvent
	informer      cache.SharedIndexInformer
	lister        v1listers.NodeLister
	topologyLabel string
}

type peerBackend struct {
	client           kiloclient.Interface
	extensionsClient apiextensions.Interface
	events           chan *mesh.PeerEvent
	informer         cache.SharedIndexInformer
	lister           v1alpha1listers.PeerLister
}

// New creates a new instance of a mesh.Backend.
func New(c kubernetes.Interface, kc kiloclient.Interface, ec apiextensions.Interface, topologyLabel string) mesh.Backend {
	ni := v1informers.NewNodeInformer(c, 5*time.Minute, nil)
	pi := v1alpha1informers.NewPeerInformer(kc, 5*time.Minute, nil)

	return &backend{
		&nodeBackend{
			client:        c,
			events:        make(chan *mesh.NodeEvent),
			informer:      ni,
			lister:        v1listers.NewNodeLister(ni.GetIndexer()),
			topologyLabel: topologyLabel,
		},
		&peerBackend{
			client:           kc,
			extensionsClient: ec,
			events:           make(chan *mesh.PeerEvent),
			informer:         pi,
			lister:           v1alpha1listers.NewPeerLister(pi.GetIndexer()),
		},
	}
}

// CleanUp removes configuration applied to the backend.
func (nb *nodeBackend) CleanUp(name string) error {
	patch := []byte("[" + strings.Join([]string{
		fmt.Sprintf(jsonRemovePatch, path.Join("/metadata", "annotations", strings.Replace(endpointAnnotationKey, "/", jsonPatchSlash, 1))),
		fmt.Sprintf(jsonRemovePatch, path.Join("/metadata", "annotations", strings.Replace(internalIPAnnotationKey, "/", jsonPatchSlash, 1))),
		fmt.Sprintf(jsonRemovePatch, path.Join("/metadata", "annotations", strings.Replace(keyAnnotationKey, "/", jsonPatchSlash, 1))),
		fmt.Sprintf(jsonRemovePatch, path.Join("/metadata", "annotations", strings.Replace(lastSeenAnnotationKey, "/", jsonPatchSlash, 1))),
		fmt.Sprintf(jsonRemovePatch, path.Join("/metadata", "annotations", strings.Replace(wireGuardIPAnnotationKey, "/", jsonPatchSlash, 1))),
		fmt.Sprintf(jsonRemovePatch, path.Join("/metadata", "annotations", strings.Replace(discoveredEndpointsKey, "/", jsonPatchSlash, 1))),
	}, ",") + "]")
	if _, err := nb.client.CoreV1().Nodes().Patch(context.TODO(), name, types.JSONPatchType, patch, metav1.PatchOptions{}); err != nil {
		return fmt.Errorf("failed to patch node: %v", err)
	}
	return nil
}

// Get gets a single Node by name.
func (nb *nodeBackend) Get(name string) (*mesh.Node, error) {
	n, err := nb.lister.Get(name)
	if err != nil {
		return nil, err
	}
	return translateNode(n, nb.topologyLabel), nil
}

// Init initializes the backend; for this backend that means
// syncing the informer cache.
func (nb *nodeBackend) Init(stop <-chan struct{}) error {
	go nb.informer.Run(stop)
	if ok := cache.WaitForCacheSync(stop, func() bool {
		return nb.informer.HasSynced()
	}); !ok {
		return errors.New("failed to sync node cache")
	}
	nb.informer.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				n, ok := obj.(*v1.Node)
				if !ok {
					// Failed to decode Node; ignoring...
					return
				}
				nb.events <- &mesh.NodeEvent{Type: mesh.AddEvent, Node: translateNode(n, nb.topologyLabel)}
			},
			UpdateFunc: func(old, obj interface{}) {
				n, ok := obj.(*v1.Node)
				if !ok {
					// Failed to decode Node; ignoring...
					return
				}
				o, ok := old.(*v1.Node)
				if !ok {
					// Failed to decode Node; ignoring...
					return
				}
				nb.events <- &mesh.NodeEvent{Type: mesh.UpdateEvent, Node: translateNode(n, nb.topologyLabel), Old: translateNode(o, nb.topologyLabel)}
			},
			DeleteFunc: func(obj interface{}) {
				n, ok := obj.(*v1.Node)
				if !ok {
					// Failed to decode Node; ignoring...
					return
				}
				nb.events <- &mesh.NodeEvent{Type: mesh.DeleteEvent, Node: translateNode(n, nb.topologyLabel)}
			},
		},
	)
	return nil
}

// List gets all the Nodes in the cluster.
func (nb *nodeBackend) List() ([]*mesh.Node, error) {
	ns, err := nb.lister.List(labels.Everything())
	if err != nil {
		return nil, err
	}
	nodes := make([]*mesh.Node, len(ns))
	for i := range ns {
		nodes[i] = translateNode(ns[i], nb.topologyLabel)
	}
	return nodes, nil
}

// Set sets the fields of a node.
func (nb *nodeBackend) Set(name string, node *mesh.Node) error {
	old, err := nb.lister.Get(name)
	if err != nil {
		return fmt.Errorf("failed to find node: %v", err)
	}
	n := old.DeepCopy()
	n.ObjectMeta.Annotations[endpointAnnotationKey] = node.Endpoint.String()
	if node.InternalIP == nil {
		n.ObjectMeta.Annotations[internalIPAnnotationKey] = ""
	} else {
		n.ObjectMeta.Annotations[internalIPAnnotationKey] = node.InternalIP.String()
	}
	n.ObjectMeta.Annotations[keyAnnotationKey] = string(node.Key)
	n.ObjectMeta.Annotations[lastSeenAnnotationKey] = strconv.FormatInt(node.LastSeen, 10)
	if node.WireGuardIP == nil {
		n.ObjectMeta.Annotations[wireGuardIPAnnotationKey] = ""
	} else {
		n.ObjectMeta.Annotations[wireGuardIPAnnotationKey] = node.WireGuardIP.String()
	}
	if node.DiscoveredEndpoints == nil {
		n.ObjectMeta.Annotations[discoveredEndpointsKey] = ""
	} else {
		discoveredEndpoints, err := json.Marshal(node.DiscoveredEndpoints)
		if err != nil {
			return err
		}
		n.ObjectMeta.Annotations[discoveredEndpointsKey] = string(discoveredEndpoints)
	}
	oldData, err := json.Marshal(old)
	if err != nil {
		return err
	}
	newData, err := json.Marshal(n)
	if err != nil {
		return err
	}
	patch, err := strategicpatch.CreateTwoWayMergePatch(oldData, newData, v1.Node{})
	if err != nil {
		return fmt.Errorf("failed to create patch for node %q: %v", n.Name, err)
	}
	if _, err = nb.client.CoreV1().Nodes().Patch(context.TODO(), name, types.StrategicMergePatchType, patch, metav1.PatchOptions{}); err != nil {
		return fmt.Errorf("failed to patch node: %v", err)
	}
	return nil
}

// Watch returns a chan of node events.
func (nb *nodeBackend) Watch() <-chan *mesh.NodeEvent {
	return nb.events
}

// translateNode translates a Kubernetes Node to a mesh.Node.
func translateNode(node *v1.Node, topologyLabel string) *mesh.Node {
	if node == nil {
		return nil
	}
	_, subnet, err := net.ParseCIDR(node.Spec.PodCIDR)
	// The subnet should only ever fail to parse if the pod CIDR has not been set,
	// so in this case set the subnet to nil and let the node be updated.
	if err != nil {
		subnet = nil
	}
	_, leader := node.ObjectMeta.Annotations[leaderAnnotationKey]
	// Allow the region to be overridden by an explicit location.
	location, ok := node.ObjectMeta.Annotations[locationAnnotationKey]
	if !ok {
		location = node.ObjectMeta.Labels[topologyLabel]
	}
	// Allow the endpoint to be overridden.
	endpoint := parseEndpoint(node.ObjectMeta.Annotations[forceEndpointAnnotationKey])
	if endpoint == nil {
		endpoint = parseEndpoint(node.ObjectMeta.Annotations[endpointAnnotationKey])
	}
	// Allow the internal IP to be overridden.
	internalIP := normalizeIP(node.ObjectMeta.Annotations[forceInternalIPAnnotationKey])
	if internalIP == nil {
		internalIP = normalizeIP(node.ObjectMeta.Annotations[internalIPAnnotationKey])
	}
	// Set the ForceInternalIP flag, if force-internal-ip annotation was set to "".
	noInternalIP := false
	if s, ok := node.ObjectMeta.Annotations[forceInternalIPAnnotationKey]; ok && (s == "" || s == "-") {
		noInternalIP = true
		internalIP = nil
	}
	// Set Wireguard PersistentKeepalive setting for the node.
	var persistentKeepalive int64
	if keepAlive, ok := node.ObjectMeta.Annotations[persistentKeepaliveKey]; !ok {
		persistentKeepalive = 0
	} else {
		if persistentKeepalive, err = strconv.ParseInt(keepAlive, 10, 64); err != nil {
			persistentKeepalive = 0
		}
	}
	var lastSeen int64
	if ls, ok := node.ObjectMeta.Annotations[lastSeenAnnotationKey]; !ok {
		lastSeen = 0
	} else {
		if lastSeen, err = strconv.ParseInt(ls, 10, 64); err != nil {
			lastSeen = 0
		}
	}
	var discoveredEndpoints map[string]*wireguard.Endpoint
	if de, ok := node.ObjectMeta.Annotations[discoveredEndpointsKey]; ok {
		err := json.Unmarshal([]byte(de), &discoveredEndpoints)
		if err != nil {
			discoveredEndpoints = nil
		}
	}

	return &mesh.Node{
		// Endpoint and InternalIP should only ever fail to parse if the
		// remote node's agent has not yet set its IP address;
		// in this case the IP will be nil and
		// the mesh can wait for the node to be updated.
		// It is valid for the InternalIP to be nil,
		// if the given node only has public IP addresses.
		Endpoint:            endpoint,
		NoInternalIP:        noInternalIP,
		InternalIP:          internalIP,
		Key:                 []byte(node.ObjectMeta.Annotations[keyAnnotationKey]),
		LastSeen:            lastSeen,
		Leader:              leader,
		Location:            location,
		Name:                node.Name,
		PersistentKeepalive: int(persistentKeepalive),
		Subnet:              subnet,
		// WireGuardIP can fail to parse if the node is not a leader or if
		// the node's agent has not yet reconciled. In either case, the IP
		// will parse as nil.
		WireGuardIP:         normalizeIP(node.ObjectMeta.Annotations[wireGuardIPAnnotationKey]),
		DiscoveredEndpoints: discoveredEndpoints,
	}
}

// translatePeer translates a Peer CRD to a mesh.Peer.
func translatePeer(peer *v1alpha1.Peer) *mesh.Peer {
	if peer == nil {
		return nil
	}
	var aips []*net.IPNet
	for _, aip := range peer.Spec.AllowedIPs {
		aip := normalizeIP(aip)
		// Skip any invalid IPs.
		if aip == nil {
			continue
		}
		aips = append(aips, aip)
	}
	var endpoint *wireguard.Endpoint
	if peer.Spec.Endpoint != nil {
		ip := net.ParseIP(peer.Spec.Endpoint.IP)
		if ip4 := ip.To4(); ip4 != nil {
			ip = ip4
		} else {
			ip = ip.To16()
		}
		if peer.Spec.Endpoint.Port > 0 && (ip != nil || peer.Spec.Endpoint.DNS != "") {
			endpoint = &wireguard.Endpoint{
				DNSOrIP: wireguard.DNSOrIP{
					DNS: peer.Spec.Endpoint.DNS,
					IP:  ip,
				},
				Port: peer.Spec.Endpoint.Port,
			}
		}
	}
	var key []byte
	if len(peer.Spec.PublicKey) > 0 {
		key = []byte(peer.Spec.PublicKey)
	}
	var psk []byte
	if len(peer.Spec.PresharedKey) > 0 {
		psk = []byte(peer.Spec.PresharedKey)
	}
	var pka int
	if peer.Spec.PersistentKeepalive > 0 {
		pka = peer.Spec.PersistentKeepalive
	}
	return &mesh.Peer{
		Name: peer.Name,
		Peer: wireguard.Peer{
			AllowedIPs:          aips,
			Endpoint:            endpoint,
			PersistentKeepalive: pka,
			PresharedKey:        psk,
			PublicKey:           key,
		},
	}
}

// CleanUp removes configuration applied to the backend.
func (pb *peerBackend) CleanUp(name string) error {
	return nil
}

// Get gets a single Peer by name.
func (pb *peerBackend) Get(name string) (*mesh.Peer, error) {
	p, err := pb.lister.Get(name)
	if err != nil {
		return nil, err
	}
	return translatePeer(p), nil
}

// Init initializes the backend; for this backend that means
// syncing the informer cache.
func (pb *peerBackend) Init(stop <-chan struct{}) error {
	// Check the presents of the CRD peers.kilo.squat.ai.
	if _, err := pb.extensionsClient.ApiextensionsV1().CustomResourceDefinitions().Get(context.TODO(), strings.Join([]string{v1alpha1.PeerPlural, v1alpha1.GroupName}, "."), metav1.GetOptions{}); err != nil {
		return fmt.Errorf("CRD is not present: %v", err)
	}

	go pb.informer.Run(stop)
	if ok := cache.WaitForCacheSync(stop, func() bool {
		return pb.informer.HasSynced()
	}); !ok {
		return errors.New("failed to sync peer cache")
	}
	pb.informer.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				p, ok := obj.(*v1alpha1.Peer)
				if !ok || p.Validate() != nil {
					// Failed to decode Peer; ignoring...
					return
				}
				pb.events <- &mesh.PeerEvent{Type: mesh.AddEvent, Peer: translatePeer(p)}
			},
			UpdateFunc: func(old, obj interface{}) {
				p, ok := obj.(*v1alpha1.Peer)
				if !ok || p.Validate() != nil {
					// Failed to decode Peer; ignoring...
					return
				}
				o, ok := old.(*v1alpha1.Peer)
				if !ok || o.Validate() != nil {
					// Failed to decode Peer; ignoring...
					return
				}
				pb.events <- &mesh.PeerEvent{Type: mesh.UpdateEvent, Peer: translatePeer(p), Old: translatePeer(o)}
			},
			DeleteFunc: func(obj interface{}) {
				p, ok := obj.(*v1alpha1.Peer)
				if !ok || p.Validate() != nil {
					// Failed to decode Peer; ignoring...
					return
				}
				pb.events <- &mesh.PeerEvent{Type: mesh.DeleteEvent, Peer: translatePeer(p)}
			},
		},
	)
	return nil
}

// List gets all the Peers in the cluster.
func (pb *peerBackend) List() ([]*mesh.Peer, error) {
	ps, err := pb.lister.List(labels.Everything())
	if err != nil {
		return nil, err
	}
	peers := make([]*mesh.Peer, len(ps))
	for i := range ps {
		// Skip invalid peers.
		if ps[i].Validate() != nil {
			continue
		}
		peers[i] = translatePeer(ps[i])
	}
	return peers, nil
}

// Set sets the fields of a peer.
func (pb *peerBackend) Set(name string, peer *mesh.Peer) error {
	old, err := pb.lister.Get(name)
	if err != nil {
		return fmt.Errorf("failed to find peer: %v", err)
	}
	p := old.DeepCopy()
	p.Spec.AllowedIPs = make([]string, len(peer.AllowedIPs))
	for i := range peer.AllowedIPs {
		p.Spec.AllowedIPs[i] = peer.AllowedIPs[i].String()
	}
	if peer.Endpoint != nil {
		var ip string
		if peer.Endpoint.IP != nil {
			ip = peer.Endpoint.IP.String()
		}
		p.Spec.Endpoint = &v1alpha1.PeerEndpoint{
			DNSOrIP: v1alpha1.DNSOrIP{
				IP:  ip,
				DNS: peer.Endpoint.DNS,
			},
			Port: peer.Endpoint.Port,
		}
	}
	p.Spec.PersistentKeepalive = peer.PersistentKeepalive
	p.Spec.PresharedKey = string(peer.PresharedKey)
	p.Spec.PublicKey = string(peer.PublicKey)
	if _, err = pb.client.KiloV1alpha1().Peers().Update(context.TODO(), p, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("failed to update peer: %v", err)
	}
	return nil
}

// Watch returns a chan of peer events.
func (pb *peerBackend) Watch() <-chan *mesh.PeerEvent {
	return pb.events
}

func normalizeIP(ip string) *net.IPNet {
	i, ipNet, err := net.ParseCIDR(ip)
	if err != nil || ipNet == nil {
		return nil
	}
	if ip4 := i.To4(); ip4 != nil {
		ipNet.IP = ip4
		return ipNet
	}
	ipNet.IP = i.To16()
	return ipNet
}

func parseEndpoint(endpoint string) *wireguard.Endpoint {
	if len(endpoint) == 0 {
		return nil
	}
	parts := strings.Split(endpoint, ":")
	if len(parts) < 2 {
		return nil
	}
	portRaw := parts[len(parts)-1]
	hostRaw := strings.Trim(strings.Join(parts[:len(parts)-1], ":"), "[]")
	port, err := strconv.ParseUint(portRaw, 10, 32)
	if err != nil {
		return nil
	}
	if len(validation.IsValidPortNum(int(port))) != 0 {
		return nil
	}
	ip := net.ParseIP(hostRaw)
	if ip == nil {
		if len(validation.IsDNS1123Subdomain(hostRaw)) == 0 {
			return &wireguard.Endpoint{DNSOrIP: wireguard.DNSOrIP{DNS: hostRaw}, Port: uint32(port)}
		}
		return nil
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	} else {
		ip = ip.To16()
	}
	return &wireguard.Endpoint{DNSOrIP: wireguard.DNSOrIP{IP: ip}, Port: uint32(port)}
}
