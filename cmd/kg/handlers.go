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
	"net"
	"net/http"
	"os"
	"os/exec"

	"github.com/kilo-io/kilo/pkg/mesh"
)

type graphHandler struct {
	mesh        *mesh.Mesh
	granularity mesh.Granularity
	hostname    *string
	subnet      *net.IPNet
}

func (h *graphHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ns, err := h.mesh.Nodes().List()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to list nodes: %v", err), http.StatusInternalServerError)
		return
	}
	ps, err := h.mesh.Peers().List()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to list peers: %v", err), http.StatusInternalServerError)
		return
	}

	nodes := make(map[string]*mesh.Node)
	for _, n := range ns {
		if n.Ready() {
			nodes[n.Name] = n
		}
	}
	if len(nodes) == 0 {
		http.Error(w, "did not find any valid Kilo nodes in the cluster", http.StatusInternalServerError)
		return
	}
	peers := make(map[string]*mesh.Peer)
	for _, p := range ps {
		if p.Ready() {
			peers[p.Name] = p
		}
	}
	topo, err := mesh.NewTopology(nodes, peers, h.granularity, *h.hostname, 0, []byte{}, h.subnet, nodes[*h.hostname].PersistentKeepalive, nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create topology: %v", err), http.StatusInternalServerError)
		return
	}

	dot, err := topo.Dot()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to generate graph: %v", err), http.StatusInternalServerError)
	}

	buf := bytes.NewBufferString(dot)

	format := r.URL.Query().Get("format")
	switch format {
	case "":
		format = "svg"
	case "dot", "gv":
		// If the raw dot data is requested, return it as string.
		// This allows client-side rendering rather than server-side.
		w.Write(buf.Bytes())
		return

	case "svg", "png", "bmp", "fig", "gif", "json", "ps":
		// Accepted format

	default:
		http.Error(w, "unsupported format", http.StatusInternalServerError)
		return
	}

	layout := r.URL.Query().Get("layout")
	switch layout {
	case "":
		layout = "circo"

	case "circo", "dot", "neato", "twopi", "fdp":
		// Accepted layout

	default:
		http.Error(w, "unsupported layout", http.StatusInternalServerError)
		return
	}

	command := exec.Command("dot", "-K"+layout, "-T"+format)
	command.Stderr = os.Stderr

	stdin, err := command.StdinPipe()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if _, err = io.Copy(stdin, buf); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err = stdin.Close(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	output, err := command.Output()
	if err != nil {
		http.Error(w, "unable to render graph", http.StatusInternalServerError)
		return
	}

	mimeType := mime.TypeByExtension("." + format)
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}

	w.Header().Add("content-type", mimeType)
	w.Write(output)
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}
