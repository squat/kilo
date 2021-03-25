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
	"net"
	"strings"

	"github.com/awalterschulze/gographviz"
	"github.com/squat/kilo/pkg/wireguard"
)

// Dot generates a Graphviz graph of the Topology in DOT fomat.
func (t *Topology) Dot() (string, error) {
	g := gographviz.NewGraph()
	g.Name = "kilo"
	if err := g.AddAttr("kilo", string(gographviz.Label), graphEscape((&net.IPNet{IP: t.wireGuardCIDR.IP.Mask(t.wireGuardCIDR.Mask), Mask: t.wireGuardCIDR.Mask}).String())); err != nil {
		return "", fmt.Errorf("failed to add label to graph")
	}
	if err := g.AddAttr("kilo", string(gographviz.LabelLOC), "t"); err != nil {
		return "", fmt.Errorf("failed to add label location to graph")
	}
	if err := g.AddAttr("kilo", string(gographviz.OutputOrder), "nodesfirst"); err != nil {
		return "", fmt.Errorf("failed to set output ordering")
	}
	if err := g.AddAttr("kilo", string(gographviz.Overlap), "false"); err != nil {
		return "", fmt.Errorf("failed to disable graph overlap")
	}
	if err := g.SetDir(true); err != nil {
		return "", fmt.Errorf("failed to set direction")
	}
	leaders := make([]string, len(t.segments))
	nodeAttrs := map[string]string{
		string(gographviz.Shape): "ellipse",
	}

	for i, s := range t.segments {
		if err := g.AddSubGraph("kilo", subGraphName(s.location), nil); err != nil {
			return "", fmt.Errorf("failed to add subgraph")
		}
		if err := g.AddAttr(subGraphName(s.location), string(gographviz.Label), graphEscape(s.location)); err != nil {
			return "", fmt.Errorf("failed to add label to subgraph")
		}
		if err := g.AddAttr(subGraphName(s.location), string(gographviz.Style), `"dashed,rounded"`); err != nil {
			return "", fmt.Errorf("failed to add style to subgraph")
		}
		for j := range s.cidrs {
			if err := g.AddNode(subGraphName(s.location), graphEscape(s.hostnames[j]), nodeAttrs); err != nil {
				return "", fmt.Errorf("failed to add node to subgraph")
			}
			var wg net.IP
			var endpoint *wireguard.Endpoint
			if j == s.leader {
				wg = s.wireGuardIP
				endpoint = s.endpoint
				if err := g.Nodes.Lookup[graphEscape(s.hostnames[j])].Attrs.Add(string(gographviz.Rank), "1"); err != nil {
					return "", fmt.Errorf("failed to add rank to node")
				}
			}
			var priv net.IP
			if s.privateIPs != nil {
				priv = s.privateIPs[j]
			}
			if err := g.Nodes.Lookup[graphEscape(s.hostnames[j])].Attrs.Add(string(gographviz.Label), nodeLabel(s.location, s.hostnames[j], s.cidrs[j], priv, wg, endpoint)); err != nil {
				return "", fmt.Errorf("failed to add label to node")
			}
		}
		meshSubGraph(g, g.Relations.SortedChildren(subGraphName(s.location)), s.leader, nil)
		leaders[i] = graphEscape(s.hostnames[s.leader])
	}
	meshGraph(g, leaders, nil)

	if err := g.AddSubGraph("kilo", graphEscape("cluster_peers"), nil); err != nil {
		return "", fmt.Errorf("failed to add peer subgraph")
	}
	if err := g.AddAttr(graphEscape("cluster_peers"), string(gographviz.Label), graphEscape("peers")); err != nil {
		return "", fmt.Errorf("failed to add label to peer subgraph")
	}
	if err := g.AddAttr(graphEscape("cluster_peers"), string(gographviz.Style), `"dashed,rounded"`); err != nil {
		return "", fmt.Errorf("failed to add style to peer subgraph")
	}
	for j := range t.peers {
		if err := g.AddNode(graphEscape("cluster_peers"), graphEscape(t.peers[j].Name), nodeAttrs); err != nil {
			return "", fmt.Errorf("failed to add peer node to peer subgraph")
		}
		if err := g.Nodes.Lookup[graphEscape(t.peers[j].Name)].Attrs.Add(string(gographviz.Label), peerLabel(t.peers[j])); err != nil {
			return "", fmt.Errorf("failed to add label to peer node")
		}
	}
	meshPeers(g, leaders, g.Relations.SortedChildren(graphEscape("cluster_peers")), nil)

	return g.String(), nil
}

func meshGraph(g *gographviz.Graph, nodes []string, attrs gographviz.Attrs) {
	if attrs == nil {
		attrs = make(gographviz.Attrs)
		attrs[gographviz.Dir] = "both"
	}
	for i := range nodes {
		for j := i + 1; j < len(nodes); j++ {
			if i == j {
				continue
			}
			g.Edges.Add(&gographviz.Edge{Src: nodes[i], Dst: nodes[j], Dir: true, Attrs: attrs})
		}
	}
}

func meshSubGraph(g *gographviz.Graph, nodes []string, leader int, attrs gographviz.Attrs) {
	if attrs == nil {
		attrs = make(gographviz.Attrs)
		attrs[gographviz.Dir] = "both"
	}
	for i := range nodes {
		if i == leader {
			continue
		}
		g.Edges.Add(&gographviz.Edge{Src: nodes[leader], Dst: nodes[i], Dir: true, Attrs: attrs})
	}
}

func meshPeers(g *gographviz.Graph, nodes, peers []string, attrs gographviz.Attrs) {
	if attrs == nil {
		attrs = make(gographviz.Attrs)
		attrs[gographviz.Dir] = "both"
		attrs[gographviz.Style] = "dashed"
	}
	for i := range nodes {
		for j := range peers {
			g.Edges.Add(&gographviz.Edge{Src: nodes[i], Dst: peers[j], Dir: true, Attrs: attrs})
		}
	}
}

func graphEscape(s string) string {
	return fmt.Sprintf("\"%s\"", s)
}

func subGraphName(name string) string {
	return graphEscape(fmt.Sprintf("cluster_location_%s", name))
}

func nodeLabel(location, name string, cidr *net.IPNet, priv, wgIP net.IP, endpoint *wireguard.Endpoint) string {
	label := []string{
		location,
		name,
		cidr.String(),
	}
	if priv != nil {
		label = append(label, priv.String())
	}
	if wgIP != nil {
		label = append(label, wgIP.String())
	}
	if endpoint != nil {
		label = append(label, endpoint.String())
	}
	return graphEscape(strings.Join(label, "\n"))
}

func peerLabel(peer *Peer) string {
	return graphEscape(fmt.Sprintf("%s\n%s\n", peer.Name, peer.Endpoint.String()))
}
