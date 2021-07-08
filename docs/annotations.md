# Annotations

The following annotations can be added to any Kubernetes Node object to configure the Kilo network.

|Name|type|examples|
|----|----|-------|
|[kilo.squat.ai/force-endpoint](#force-endpoint)|host:port|`55.55.55.55:51820`, `example.com:1337`|
|[kilo.squat.ai/force-internal-ip](#force-internal-ip)|CIDR|`55.55.55.55/32`, `"-"`,`""`|
|[kilo.squat.ai/leader](#leader)|string|`""`, `true`|
|[kilo.squat.ai/location](#location)|string|`gcp-east`, `lab`|
|[kilo.squat.ai/persistent-keepalive](#persistent-keepalive)|uint|`10`|
|[kilo.squat.ai/allowed-location-ips](#allowed-location-ips)|CIDR|`66.66.66.66/32`|

### force-endpoint
In order to create links between locations, Kilo requires at least one node in each location to have an endpoint, ie a `host:port` combination, that is routable from the other locations.
If the locations are in different cloud providers or in different private networks, then the `host` portion of the endpoint should be a publicly accessible IP address, or a DNS name that resolves to a public IP, so that the other locations can route packets to it.
The Kilo agent running on each node will use heuristics to automatically detect an external IP address for the node and correctly configure its endpoint; however, in some circumstances it may be necessary to explicitly configure the endpoint to use, for example:
 * _no automatic public IP on ethernet device_: on some cloud providers it is common for nodes to be allocated a public IP address but for the Ethernet devices to only be automatically configured with the private network address; in this case the allocated public IP address should be specified;
 * _multiple public IP addresses_: if a node has multiple public IPs but one is preferred, then the preferred IP address should be specified;
 * _IPv6_: if a node has both public IPv4 and IPv6 addresses and the Kilo network should operate over IPv6, then the IPv6 address should be specified;
 * _dynamic IP address_: if a node has a dynamically allocated public IP address, for example an IP leased from a network provider, then a dynamic DNS name can be given can be given and Kilo will periodically lookup the IP to keep the endpoint up-to-date;
 * _override port_: if a node should listen on a specific port that is different from the mesh's default WireGuard port, then this annotation can be used to override the port; this can be useful, for example, to ensure that two nodes operating behind the same port-forwarded NAT gateway can each be allocated a different port.

### force-internal-ip
Kilo routes packets destined for nodes inside the same logical location using the node's internal IP address.
The Kilo agent running on each node will use heuristics to automatically detect a private IP address for the node; however, in some circumstances it may be necessary to explicitly configure the IP address, for example:
 * _multiple private IP addresses_: if a node has multiple private IPs but one is preferred, then the preferred IP address should be specified;
 * _IPv6_: if a node has both private IPv4 and IPv6 addresses and the Kilo network should operate over IPv6, then the IPv6 address should be specified.
 * _disable private IP with "-" or ""_: a node has a private and public address, but the private address ought to be ignored.

### leader
By default, Kilo creates a network mesh at the data-center granularity.
This means that one leader node is selected from each location to be an edge server and act as the gateway to other locations; the network topology will be a full mesh between leaders.
Kilo automatically selects the leader for each location in a stable and deterministic manner to avoid churn in the network configuration, while giving preference to nodes that are known to have public IP addresses.
In some situations it may be desirable to manually select the leader for a location, for example:
 * _firewall_: Kilo requires an open UDP port, which defaults to 51820, to communicate between locations; if only one node is configured to have that port open, then that node should be given the leader annotation;
 * _bandwidth_: if certain nodes in the cluster have a higher bandwidth or lower latency Internet connection, then those nodes should be given the leader annotation.

> **Note**: multiple nodes within a single location can be given the leader annotation; in this case, Kilo will select one leader from the set of annotated nodes.

### location
Kilo allows nodes in different logical or physical locations to route packets to one-another.
In order to know what connections to create, Kilo needs to know which nodes are in each location.
Kilo will try to infer each node's location from the [topology.kubernetes.io/region](https://kubernetes.io/docs/reference/kubernetes-api/labels-annotations-taints/#topologykubernetesioregion) node label.
If the label is not present for a node, for example if running a bare-metal cluster or on an unsupported cloud provider, then the location annotation should be specified.

> **Note**: all nodes without a defined location will be considered to be in the default location `""`.

### persistent-keepalive
In certain deployments, cluster nodes may be located behind NAT or a firewall, e.g. edge nodes located behind a commodity router.
In these scenarios, the nodes behind NAT can send packets to the nodes outside of the NATed network, however the outside nodes can only send packets into the NATed network as long as the NAT mapping remains valid.
In order for a node behind NAT to receive packets from nodes outside of the NATed network, it must maintain the NAT mapping by regularly sending packets to those nodes, ie by sending _keepalives_.
The frequency of emission of these keepalive packets can be controlled by setting the persistent-keepalive annotation on the node behind NAT.
The annotated node will use the specified value will as the persistent-keepalive interval for all of its peers.
For more background, [see the WireGuard documentation on NAT and firewall traversal](https://www.wireguard.com/quickstart/#nat-and-firewall-traversal-persistence).

### allowed-location-ips
It is possible to add allowed-location-ips to a location by annotating any node within that location.
Adding allowed-location-ips to a location makes these IPs routable from other locations as well.

In an example deployment of Kilo with two locations A and B, a printer in location A can be accessible from nodes and pods in location B.
Additionally, Kilo Peers can use the printer in location A.
