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
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path"
	"strconv"
	"strings"
	"time"

	crdutils "github.com/ant31/crd-validation/pkg"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
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
	Backend                         = "kubernetes"
	externalIPAnnotationKey         = "kilo.squat.ai/external-ip"
	forceExternalIPAnnotationKey    = "kilo.squat.ai/force-external-ip"
	forceInternalIPAnnotationKey    = "kilo.squat.ai/force-internal-ip"
	internalIPAnnotationKey         = "kilo.squat.ai/internal-ip"
	keyAnnotationKey                = "kilo.squat.ai/key"
	lastSeenAnnotationKey           = "kilo.squat.ai/last-seen"
	leaderAnnotationKey             = "kilo.squat.ai/leader"
	locationAnnotationKey           = "kilo.squat.ai/location"
	wireGuardIPAnnotationKey        = "kilo.squat.ai/wireguard-ip"
	wireGuardPersistentKeepAliveKey = "kilo.squat.ai/wireguard-persistent-keepalive"

	regionLabelKey  = "topology.kubernetes.io/region"
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
	client   kubernetes.Interface
	events   chan *mesh.NodeEvent
	informer cache.SharedIndexInformer
	lister   v1listers.NodeLister
}

type peerBackend struct {
	client           kiloclient.Interface
	extensionsClient apiextensions.Interface
	events           chan *mesh.PeerEvent
	informer         cache.SharedIndexInformer
	lister           v1alpha1listers.PeerLister
}

// New creates a new instance of a mesh.Backend.
func New(c kubernetes.Interface, kc kiloclient.Interface, ec apiextensions.Interface) mesh.Backend {
	ni := v1informers.NewNodeInformer(c, 5*time.Minute, nil)
	pi := v1alpha1informers.NewPeerInformer(kc, 5*time.Minute, nil)

	return &backend{
		&nodeBackend{
			client:   c,
			events:   make(chan *mesh.NodeEvent),
			informer: ni,
			lister:   v1listers.NewNodeLister(ni.GetIndexer()),
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
		fmt.Sprintf(jsonRemovePatch, path.Join("/metadata", "annotations", strings.Replace(externalIPAnnotationKey, "/", jsonPatchSlash, 1))),
		fmt.Sprintf(jsonRemovePatch, path.Join("/metadata", "annotations", strings.Replace(internalIPAnnotationKey, "/", jsonPatchSlash, 1))),
		fmt.Sprintf(jsonRemovePatch, path.Join("/metadata", "annotations", strings.Replace(keyAnnotationKey, "/", jsonPatchSlash, 1))),
		fmt.Sprintf(jsonRemovePatch, path.Join("/metadata", "annotations", strings.Replace(lastSeenAnnotationKey, "/", jsonPatchSlash, 1))),
		fmt.Sprintf(jsonRemovePatch, path.Join("/metadata", "annotations", strings.Replace(wireGuardIPAnnotationKey, "/", jsonPatchSlash, 1))),
	}, ",") + "]")
	if _, err := nb.client.CoreV1().Nodes().Patch(name, types.JSONPatchType, patch); err != nil {
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
	return translateNode(n), nil
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
				nb.events <- &mesh.NodeEvent{Type: mesh.AddEvent, Node: translateNode(n)}
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
				nb.events <- &mesh.NodeEvent{Type: mesh.UpdateEvent, Node: translateNode(n), Old: translateNode(o)}
			},
			DeleteFunc: func(obj interface{}) {
				n, ok := obj.(*v1.Node)
				if !ok {
					// Failed to decode Node; ignoring...
					return
				}
				nb.events <- &mesh.NodeEvent{Type: mesh.DeleteEvent, Node: translateNode(n)}
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
		nodes[i] = translateNode(ns[i])
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
	n.ObjectMeta.Annotations[externalIPAnnotationKey] = node.ExternalIP.String()
	n.ObjectMeta.Annotations[internalIPAnnotationKey] = node.InternalIP.String()
	n.ObjectMeta.Annotations[keyAnnotationKey] = string(node.Key)
	n.ObjectMeta.Annotations[lastSeenAnnotationKey] = strconv.FormatInt(node.LastSeen, 10)
	if node.WireGuardIP == nil {
		n.ObjectMeta.Annotations[wireGuardIPAnnotationKey] = ""
	} else {
		n.ObjectMeta.Annotations[wireGuardIPAnnotationKey] = node.WireGuardIP.String()
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
	if _, err = nb.client.CoreV1().Nodes().Patch(name, types.StrategicMergePatchType, patch); err != nil {
		return fmt.Errorf("failed to patch node: %v", err)
	}
	return nil
}

// Watch returns a chan of node events.
func (nb *nodeBackend) Watch() <-chan *mesh.NodeEvent {
	return nb.events
}

// translateNode translates a Kubernetes Node to a mesh.Node.
func translateNode(node *v1.Node) *mesh.Node {
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
		location = node.ObjectMeta.Labels[regionLabelKey]
	}
	// Allow the IPs to be overridden.
	externalIP, ok := node.ObjectMeta.Annotations[forceExternalIPAnnotationKey]
	if !ok {
		externalIP = node.ObjectMeta.Annotations[externalIPAnnotationKey]
	}
	internalIP, ok := node.ObjectMeta.Annotations[forceInternalIPAnnotationKey]
	if !ok {
		internalIP = node.ObjectMeta.Annotations[internalIPAnnotationKey]
	}
	// Set Wireguard PersistentKeepAliveKey.
	var wireGuardPersistentKeepAlive int64
	if wgKeepAlive, ok := node.ObjectMeta.Annotations[wireGuardIPAnnotationKey]; !ok {
		wireGuardPersistentKeepAlive = 0
	} else {
		if wireGuardPersistentKeepAlive, err = strconv.ParseInt(wgKeepAlive, 10, 64); err != nil {
			wireGuardPersistentKeepAlive = 0
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
	return &mesh.Node{
		// ExternalIP and InternalIP should only ever fail to parse if the
		// remote node's agent has not yet set its IP address;
		// in this case the IP will be nil and
		// the mesh can wait for the node to be updated.
		ExternalIP: normalizeIP(externalIP),
		InternalIP: normalizeIP(internalIP),
		Key:        []byte(node.ObjectMeta.Annotations[keyAnnotationKey]),
		LastSeen:   lastSeen,
		Leader:     leader,
		Location:   location,
		Name:       node.Name,
		Subnet:     subnet,
		// WireGuardIP can fail to parse if the node is not a leader or if
		// the node's agent has not yet reconciled. In either case, the IP
		// will parse as nil.
		WireGuardIP:                  normalizeIP(node.ObjectMeta.Annotations[wireGuardIPAnnotationKey]),
		WireGuardPersistentKeepAlive: wireGuardPersistentKeepAlive,
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
		if peer.Spec.Endpoint.Port > 0 && ip != nil {
			endpoint = &wireguard.Endpoint{
				IP:   ip,
				Port: peer.Spec.Endpoint.Port,
			}
		}
	}
	var key []byte
	if len(peer.Spec.PublicKey) > 0 {
		key = []byte(peer.Spec.PublicKey)
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
			PublicKey:           key,
			PersistentKeepalive: pka,
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
	// Register CRD.
	crd := crdutils.NewCustomResourceDefinition(crdutils.Config{
		SpecDefinitionName:    "github.com/squat/kilo/pkg/k8s/apis/kilo/v1alpha1.Peer",
		EnableValidation:      true,
		ResourceScope:         string(v1beta1.ClusterScoped),
		Group:                 v1alpha1.GroupName,
		Kind:                  v1alpha1.PeerKind,
		Version:               v1alpha1.SchemeGroupVersion.Version,
		Plural:                v1alpha1.PeerPlural,
		ShortNames:            v1alpha1.PeerShortNames,
		GetOpenAPIDefinitions: v1alpha1.GetOpenAPIDefinitions,
	})
	crd.Spec.Subresources.Scale = nil
	crd.Spec.Subresources.Status = nil

	_, err := pb.extensionsClient.ApiextensionsV1beta1().CustomResourceDefinitions().Create(crd)
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("failed to create CRD: %v", err)
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
		p.Spec.Endpoint = &v1alpha1.PeerEndpoint{
			IP:   peer.Endpoint.IP.String(),
			Port: peer.Endpoint.Port,
		}
	}
	p.Spec.PersistentKeepalive = peer.PersistentKeepalive
	p.Spec.PublicKey = string(peer.PublicKey)
	if _, err = pb.client.KiloV1alpha1().Peers().Update(p); err != nil {
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
