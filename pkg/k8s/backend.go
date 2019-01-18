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
	"strings"
	"time"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	v1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	v1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/squat/kilo/pkg/mesh"
)

const (
	// Backend is the name of this mesh backend.
	Backend                      = "kubernetes"
	externalIPAnnotationKey      = "kilo.squat.ai/external-ip"
	forceExternalIPAnnotationKey = "kilo.squat.ai/force-external-ip"
	internalIPAnnotationKey      = "kilo.squat.ai/internal-ip"
	keyAnnotationKey             = "kilo.squat.ai/key"
	leaderAnnotationKey          = "kilo.squat.ai/leader"
	locationAnnotationKey        = "kilo.squat.ai/location"
	regionLabelKey               = "failure-domain.beta.kubernetes.io/region"
	jsonPatchSlash               = "~1"
	jsonRemovePatch              = `{"op": "remove", "path": "%s"}`
)

type backend struct {
	client   kubernetes.Interface
	events   chan *mesh.Event
	informer cache.SharedIndexInformer
	lister   v1listers.NodeLister
}

// New creates a new instance of a mesh.Backend.
func New(client kubernetes.Interface) mesh.Backend {
	informer := v1informers.NewNodeInformer(client, 5*time.Minute, nil)

	b := &backend{
		client:   client,
		events:   make(chan *mesh.Event),
		informer: informer,
		lister:   v1listers.NewNodeLister(informer.GetIndexer()),
	}

	return b
}

// CleanUp removes configuration applied to the backend.
func (b *backend) CleanUp(name string) error {
	patch := []byte("[" + strings.Join([]string{
		fmt.Sprintf(jsonRemovePatch, path.Join("/metadata", "annotations", strings.Replace(externalIPAnnotationKey, "/", jsonPatchSlash, 1))),
		fmt.Sprintf(jsonRemovePatch, path.Join("/metadata", "annotations", strings.Replace(internalIPAnnotationKey, "/", jsonPatchSlash, 1))),
		fmt.Sprintf(jsonRemovePatch, path.Join("/metadata", "annotations", strings.Replace(keyAnnotationKey, "/", jsonPatchSlash, 1))),
	}, ",") + "]")
	if _, err := b.client.CoreV1().Nodes().Patch(name, types.JSONPatchType, patch); err != nil {
		return fmt.Errorf("failed to patch node: %v", err)
	}
	return nil
}

// Get gets a single Node by name.
func (b *backend) Get(name string) (*mesh.Node, error) {
	n, err := b.lister.Get(name)
	if err != nil {
		return nil, err
	}
	return translateNode(n), nil
}

// Init initializes the backend; for this backend that means
// syncing the informer cache.
func (b *backend) Init(stop <-chan struct{}) error {
	go b.informer.Run(stop)
	if ok := cache.WaitForCacheSync(stop, func() bool {
		return b.informer.HasSynced()
	}); !ok {
		return errors.New("failed to start sync node cache")
	}
	b.informer.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				n, ok := obj.(*v1.Node)
				if !ok {
					// Failed to decode Node; ignoring...
					return
				}
				b.events <- &mesh.Event{Type: mesh.AddEvent, Node: translateNode(n)}
			},
			UpdateFunc: func(_, obj interface{}) {
				n, ok := obj.(*v1.Node)
				if !ok {
					// Failed to decode Node; ignoring...
					return
				}
				b.events <- &mesh.Event{Type: mesh.UpdateEvent, Node: translateNode(n)}
			},
			DeleteFunc: func(obj interface{}) {
				n, ok := obj.(*v1.Node)
				if !ok {
					// Failed to decode Node; ignoring...
					return
				}
				b.events <- &mesh.Event{Type: mesh.DeleteEvent, Node: translateNode(n)}
			},
		},
	)
	return nil
}

// List gets all the Nodes in the cluster.
func (b *backend) List() ([]*mesh.Node, error) {
	ns, err := b.lister.List(labels.Everything())
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
func (b *backend) Set(name string, node *mesh.Node) error {
	old, err := b.lister.Get(name)
	if err != nil {
		return fmt.Errorf("failed to find node: %v", err)
	}
	n := old.DeepCopy()
	n.ObjectMeta.Annotations[externalIPAnnotationKey] = node.ExternalIP.String()
	n.ObjectMeta.Annotations[internalIPAnnotationKey] = node.InternalIP.String()
	n.ObjectMeta.Annotations[keyAnnotationKey] = string(node.Key)
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
	if _, err = b.client.CoreV1().Nodes().Patch(name, types.StrategicMergePatchType, patch); err != nil {
		return fmt.Errorf("failed to patch node: %v", err)
	}
	return nil
}

// Watch returns a chan of node events.
func (b *backend) Watch() <-chan *mesh.Event {
	return b.events
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
	// Allow the external IP to be overridden.
	externalIP, ok := node.ObjectMeta.Annotations[forceExternalIPAnnotationKey]
	if !ok {
		externalIP = node.ObjectMeta.Annotations[externalIPAnnotationKey]
	}
	return &mesh.Node{
		// ExternalIP and InternalIP should only ever fail to parse if the
		// remote node's mesh has not yet set its IP address;
		// in this case the IP will be nil and
		// the mesh can wait for the node to be updated.
		ExternalIP: normalizeIP(externalIP),
		InternalIP: normalizeIP(node.ObjectMeta.Annotations[internalIPAnnotationKey]),
		Key:        []byte(node.ObjectMeta.Annotations[keyAnnotationKey]),
		Leader:     leader,
		Location:   location,
		Name:       node.Name,
		Subnet:     subnet,
	}
}

func normalizeIP(ip string) *net.IPNet {
	i, ipNet, _ := net.ParseCIDR(ip)
	if ipNet == nil {
		return ipNet
	}
	if ip4 := i.To4(); ip4 != nil {
		ipNet.IP = ip4
		return ipNet
	}
	ipNet.IP = i.To16()
	return ipNet
}
