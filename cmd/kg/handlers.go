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

package main

import (
	"bytes"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"os/exec"

	"github.com/squat/kilo/pkg/mesh"
)

type graphHandler struct {
	mesh        *mesh.Mesh
	granularity mesh.Granularity
}

func (h *graphHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ns, err := h.mesh.Nodes().List()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to list nodes: %v", err), 500)
		return
	}
	ps, err := h.mesh.Peers().List()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to list peers: %v", err), 500)
		return
	}

	var hostname string
	subnet := mesh.DefaultKiloSubnet
	nodes := make(map[string]*mesh.Node)
	for _, n := range ns {
		if n.Ready() {
			nodes[n.Name] = n
			hostname = n.Name
		}
		if n.WireGuardIP != nil {
			subnet = n.WireGuardIP
		}
	}
	subnet.IP = subnet.IP.Mask(subnet.Mask)
	if len(nodes) == 0 {
		http.Error(w, "did not find any valid Kilo nodes in the cluster", 500)
		return
	}
	peers := make(map[string]*mesh.Peer)
	for _, p := range ps {
		if p.Ready() {
			peers[p.Name] = p
		}
	}
	topo, err := mesh.NewTopology(nodes, peers, h.granularity, hostname, 0, []byte{}, subnet, nodes[hostname].PersistentKeepalive, nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create topology: %v", err), 500)
		return
	}

	dot, err := topo.Dot()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to generate graph: %v", err), 500)
	}

	buf := bytes.NewBufferString(dot)

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "png"
	} else if format == ".dot" || format == ".gv" {
		// If the raw dot data is requested, return it as string.
		// This allows client-side rendering rather than server-side.
		w.Write(buf.Bytes())
		return
	}

	command := exec.Command("dot", "-T"+format)
	command.Stderr = os.Stderr

	stdin, err := command.StdinPipe()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	_, err = io.Copy(stdin, buf)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	err = stdin.Close()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	output, err := command.Output()
	if err != nil {
		http.Error(w, fmt.Sprintf("unable to execute dot: %v (is graphviz package installed?)", err), 500)
		return
	}

	mimeType := mime.TypeByExtension("." + format)
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}

	w.Write(output)
}

type healthHandler struct {
}

func (h *healthHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}
