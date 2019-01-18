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

	"github.com/awalterschulze/gographviz"
)

// Dot generates a Graphviz graph of the Topology in DOT fomat.
func (t *Topology) Dot() (string, error) {
	g := gographviz.NewGraph()
	g.Name = "kilo"
	if err := g.AddAttr("kilo", string(gographviz.Label), graphEscape(t.subnet.String())); err != nil {
		return "", fmt.Errorf("failed to add label to graph")
	}
	if err := g.AddAttr("kilo", string(gographviz.LabelLOC), "t"); err != nil {
		return "", fmt.Errorf("failed to add label location to graph")
	}
	if err := g.AddAttr("kilo", string(gographviz.Overlap), "false"); err != nil {
		return "", fmt.Errorf("failed to disable graph overlap")
	}
	if err := g.SetDir(true); err != nil {
		return "", fmt.Errorf("failed to set direction")
	}
	leaders := make([]string, len(t.Segments))
	nodeAttrs := map[string]string{
		string(gographviz.Shape): "ellipse",
	}
	for i, s := range t.Segments {
		if err := g.AddSubGraph("kilo", subGraphName(s.Location), nil); err != nil {
			return "", fmt.Errorf("failed to add subgraph")
		}
		if err := g.AddAttr(subGraphName(s.Location), string(gographviz.Label), graphEscape(s.Location)); err != nil {
			return "", fmt.Errorf("failed to add label to subgraph")
		}
		if err := g.AddAttr(subGraphName(s.Location), string(gographviz.Style), `"dashed,rounded"`); err != nil {
			return "", fmt.Errorf("failed to add style to subgraph")
		}
		for j := range s.cidrs {
			if err := g.AddNode(subGraphName(s.Location), graphEscape(s.hostnames[j]), nodeAttrs); err != nil {
				return "", fmt.Errorf("failed to add node to subgraph")
			}
			var wg net.IP
			if j == s.leader {
				wg = s.wireGuardIP
				if err := g.Nodes.Lookup[graphEscape(s.hostnames[j])].Attrs.Add(string(gographviz.Rank), "1"); err != nil {
					return "", fmt.Errorf("failed to add rank to node")
				}
			}
			if err := g.Nodes.Lookup[graphEscape(s.hostnames[j])].Attrs.Add(string(gographviz.Label), nodeLabel(s.Location, s.hostnames[j], s.cidrs[j], s.privateIPs[j], wg)); err != nil {
				return "", fmt.Errorf("failed to add label to node")
			}
		}
		meshSubGraph(g, g.Relations.SortedChildren(subGraphName(s.Location)), s.leader)
		leaders[i] = graphEscape(s.hostnames[s.leader])
	}
	meshSubGraph(g, leaders, 0)
	return g.String(), nil
}

func meshSubGraph(g *gographviz.Graph, nodes []string, leader int) {
	for i := range nodes {
		if i == leader {
			continue
		}
		a := make(gographviz.Attrs)
		a[gographviz.Dir] = "both"
		g.Edges.Add(&gographviz.Edge{Src: nodes[leader], Dst: nodes[i], Dir: true, Attrs: a})
	}
}

func graphEscape(s string) string {
	return fmt.Sprintf("\"%s\"", s)
}

func subGraphName(name string) string {
	return graphEscape(fmt.Sprintf("cluster_%s", name))
}

func nodeLabel(location, name string, cidr *net.IPNet, priv, wgIP net.IP) string {
	var wg string
	if wgIP != nil {
		wg = wgIP.String()
	}
	return graphEscape(fmt.Sprintf("%s\n%s\n%s\n%s\n%s", location, name, cidr.String(), priv.String(), wg))
}
