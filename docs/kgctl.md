# kgctl

Kilo provides a command line tool for inspecting and interacting with clusters: `kgctl`.
This tool can be used to understand a mesh's topology, get the WireGuard configuration for a peer, or graph a cluster.
`kgctl` requires a Kubernetes configuration file to be provided, either by setting the `KUBECONFIG` environment variable or by providing the `--kubeconfig` flag.

## Installation

The `kgctl` binary is automatically compiled for Linux, macOS, and Windows for every release of Kilo and can be downloaded from [the GitHub releases page](https://github.com/squat/kilo/releases/latest).

### Building from Source
Kilo is written in Golang and as a result the [Go toolchain must be installed](https://golang.org/doc/install) in order to build the `kgctl` binary.
To download the Kilo source code and then build and install `kgctl` using the latest commit all with a single command, run:

```shell
go install github.com/squat/kilo/cmd/kgctl@latest
```

Alternatively, `kgctl` can be built and installed based on specific version of the code by specifying a Git tag or hash, e.g.:

```shell
go install github.com/squat/kilo/cmd/kgctl@0.2.0
```

When working on Kilo locally, it can be helpful to build and test the `kgctl` binary as part of the development cycle.
In order to build a binary from a local checkout of the Git repository, run:

```shell
make
```

This will produce a `kgctl` binary at `./bin/<your-os>/<your-architecture>/kgctl`.

## Commands

|Command|Syntax|Description|
|----|----|-------|
|[graph](#graph)|`kgctl graph [flags]`|Produce a graph in GraphViz format representing the topology of the cluster.|
|[showconf](#showconf)|`kgctl showconf ( node \| peer ) NAME [flags]`|Show the WireGuard configuration for a node or peer in the mesh.|


### graph

The `graph` command generates a graph in GraphViz format representing the Kilo mesh.
This graph can be helpful in understanding or debugging the topology of a network.
Example:

```shell
kgctl graph
```

This will produce some output in the DOT graph description language, e.g.:

```dot
digraph kilo {
	label="10.2.4.0/24";
	labelloc=t;
	outputorder=nodesfirst;
	overlap=false;
	"ip-10-0-6-7"->"ip-10-0-6-146"[ dir=both ];
	"ip-10-1-13-74"->"ip-10-1-20-76"[ dir=both ];
	"ip-10-0-6-7"->"ip-10-1-13-74"[ dir=both ];
	"ip-10-0-6-7"->"squat"[ dir=both, style=dashed ];
	"ip-10-1-13-74"->"squat"[ dir=both, style=dashed ];

# ...

}
;
```

To render the graph, use one of the GraphViz layout tools, e.g. `circo`:

```shell
kgctl graph | circo -Tsvg > cluster.svg
```

This will generate an SVG like:

<img src="./graphs/location.svg" />

### showconf

The `showconf` command outputs the WireGuard configuration for a node or peer in the cluster, i.e. the configuration that the node or peer would need to set on its local WireGuard interface in order to participate in the mesh.
Example:

```shell
NODE=master # the name of a node
kgctl showconf node $NODE
```

This will produce some output in INI format, e.g.

```ini
[Interface]
ListenPort = 51820

[Peer]
AllowedIPs = 10.2.0.0/24, 10.1.13.74/32, 10.2.4.0/24, 10.1.20.76/32, 10.4.0.2/32
Endpoint = 3.120.246.76:51820
PersistentKeepalive = 0
PublicKey = IgDTEvasUvxisSAmfBKh8ngFmc2leZBvkRwYBhkybUg=
```

The `--as-peer` flag modifies the behavior of the command so that it outputs the configuration that a different WireGuard interface would need in order to communicate with the specified node or peer.
When further combined with the `--output yaml` flag, this command can be useful to register a node in one cluster as a peer of another cluster, e.g.:

```shell
NODE=master # the name of a node
kgctl --kubeconfig $KUBECONFIG1 showconf node $NODE --as-peer --output yaml | kubectl --kubeconfig $KUBECONFIG2 apply -f -
```
