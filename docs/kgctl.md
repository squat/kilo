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


### Binary Packages

#### Arch Linux

Install `kgctl` from the Arch User Repository using an AUR helper like `paru` or `yay`:

```shell
paru -S kgctl-bin
```

#### Arkade

The [arkade](https://github.com/alexellis/arkade) CLI can be used to install `kgctl` on any OS and architecture:

```shell
arkade get kgctl
```

## Commands

|Command|Syntax|Description|
|----|----|-------|
|[connect](#connect)|`kgctl connect <peer-name> [flags]`|Connect the host to the cluster, setting up the required interfaces, routes, and keys.|
|[graph](#graph)|`kgctl graph [flags]`|Produce a graph in GraphViz format representing the topology of the cluster.|
|[showconf](#showconf)|`kgctl showconf ( node \| peer ) <name> [flags]`|Show the WireGuard configuration for a node or peer in the mesh.|

### connect

The `connect` command configures the local host as a WireGuard Peer of the cluster and applies all of the necessary networking configuration to connect to the cluster.
As long as the process is running, it will watch the cluster for changes and automatically manage the configuration for new or updated Peers and Nodes.
If the given Peer name does not exist in the cluster, the command will register a new Peer and generate the necessary WireGuard keys.
When the command exits, all of the configuration, including newly registered Peers, is cleaned up.

Example:

```shell
PEER_NAME=laptop
SERVICECIDR=10.43.0.0/16
kgctl connect $PEER_NAME --allowed-ips $SERVICECIDR
```

The local host is now connected to the cluster and all IPs from the cluster and any registered Peers are fully routable.
When combined with the `--clean-up false` flag, the configuration produced by the command is persistent and will remain in effect even after the process is stopped.

With the service CIDR of the cluster routable from the local host, Kubernetes DNS names can now be resolved by the cluster DNS provider.
For example, the following snippet could be used to resolve the clusterIP of the Kubernetes API:
```shell
dig @$(kubectl get service -n kube-system kube-dns -o=jsonpath='{.spec.clusterIP}') kubernetes.default.svc.cluster.local +short
# > 10.43.0.1
```

For convenience, the cluster DNS provider's IP address can be configured as the local host's DNS server, making Kubernetes DNS names easily resolvable.
For example, if using `systemd-resolved`, the following snippet could be used:
```shell
systemd-resolve --interface kilo0 --set-dns $(kubectl get service -n kube-system kube-dns -o=jsonpath='{.spec.clusterIP}') --set-domain cluster.local
# Now all lookups for DNS names ending in `.cluster.local` will be routed over the `kilo0` interface to the cluster DNS provider.
dig kubernetes.default.svc.cluster.local +short
# > 10.43.0.1
```

> **Note**: The `connect` command is currently only supported on Linux.

> **Note**: The `connect` command requires the `CAP_NET_ADMIN` capability in order to configure the host's networking stack; unprivileged users will need to use `sudo` or similar tools.

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
