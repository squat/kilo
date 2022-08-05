# kg

`kg` is the Kilo agent that runs on every Kubernetes node in a Kilo mesh.
It performs several key functions, including:
* adding the node to the Kilo mesh;
* installing CNI configuration on the node;
* configuring the WireGuard network interface; and
* maintaining routing table entries and iptables rules.

`kg` is typically installed on all nodes of a Kubernetes cluster using a DaemonSet.
Example manifests can be found [in the manifests directory](https://github.com/squat/kilo/tree/main/manifests).

## Usage

The behavior of `kg` can be configured using the command line flags listed below.

[embedmd]:# (../tmp/help.txt)
```txt
kg is the Kilo agent.
		It runs on every node of a cluster,
		setting up the public and private keys for the VPN
		as well as the necessary rules to route packets between locations.

Usage:
  kg [flags]
  kg [command]

Available Commands:
  completion  generate the autocompletion script for the specified shell
  help        Help about any command
  version     Print the version and exit.
  webhook     webhook starts a HTTPS server to validate updates and creations of Kilo peers.

Flags:
      --backend string                 The backend for the mesh. Possible values: kubernetes (default "kubernetes")
      --clean-up-interface             Should Kilo delete its interface when it shuts down?
      --cni                            Should Kilo manage the node's CNI configuration? (default true)
      --cni-path string                Path to CNI config. (default "/etc/cni/net.d/10-kilo.conflist")
      --compatibility string           Should Kilo run in compatibility mode? Possible values: flannel
      --create-interface               Should kilo create an interface on startup? (default true)
      --encapsulate string             When should Kilo encapsulate packets within a location? Possible values: never, crosssubnet, always (default "always")
  -h, --help                           help for kg
      --hostname string                Hostname of the node on which this process is running.
      --interface string               Name of the Kilo interface to use; if it does not exist, it will be created. (default "kilo0")
      --iptables-forward-rules         Add default accept rules to the FORWARD chain in iptables. Warning: this may break firewalls with a deny all policy and is potentially insecure!
      --kubeconfig string              Path to kubeconfig.
      --listen string                  The address at which to listen for health and metrics. (default ":1107")
      --local                          Should Kilo manage routes within a location? (default true)
      --log-level string               Log level to use. Possible values: all, debug, info, warn, error, none (default "info")
      --master string                  The address of the Kubernetes API server (overrides any value in kubeconfig).
      --mesh-granularity string        The granularity of the network mesh to create. Possible values: location, full, cross (default "location")
      --mtu uint                       The MTU of the WireGuard interface created by Kilo. (default 1420)
      --port int                       The port over which WireGuard peers should communicate. (default 51820)
      --prioritise-private-addresses   Prefer to assign a private IP address to the node's endpoint.
      --resync-period duration         How often should the Kilo controllers reconcile? (default 30s)
      --subnet string                  CIDR from which to allocate addresses for WireGuard interfaces. (default "10.4.0.0/16")
      --topology-label string          Kubernetes node label used to group nodes into logical locations. (default "topology.kubernetes.io/region")
      --version                        Print version and exit

```
