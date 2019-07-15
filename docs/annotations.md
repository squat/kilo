# Annotations

The following annotations can be added to any Kubernetes Node object to configure the Kilo network.

|Name|type|example|
|----|----|-------|
|[kilo.squat.ai/force-external-ip](#force-external-ip)|CIDR|`"55.55.55.55/32"`|
|[kilo.squat.ai/force-internal-ip](#force-internal-ip)|CIDR|`"55.55.55.55/32"`|
|[kilo.squat.ai/leader](#leader)|string|`""`|
|[kilo.squat.ai/location](#location)|string|`"gcp-east"`|

### force-external-ip
Kilo requires at least one node in each location to have a publicly accessible IP address in order to create links to other locations.
The Kilo agent running on each node will use heuristics to automatically detect an external IP address for the node; however, in some circumstances it may be necessary to explicitly configure the IP address, for example:
 * _no automatic public IP on ethernet device_: on some cloud providers it is common for nodes to be allocated a public IP address but for the Ethernet devices to only be automatically configured with the private network address; in this case the allocated public IP address should be specified;
 * _multiple public IP addresses_: if a node has multiple public IPs but one is preferred, then the preferred IP address should be specified;
 * _IPv6_: if a node has both public IPv4 and IPv6 addresses and the Kilo network should operate over IPv6, then the IPv6 address should be specified.

### force-internal-ip
Kilo routes packets destined for nodes inside the same logical location using the node's internal IP address.
The Kilo agent running on each node will use heuristics to automatically detect a private IP address for the node; however, in some circumstances it may be necessary to explicitly configure the IP address, for example:
 * _multiple private IP addresses_: if a node has multiple private IPs but one is preferred, then the preferred IP address should be specified;
 * _IPv6_: if a node has both private IPv4 and IPv6 addresses and the Kilo network should operate over IPv6, then the IPv6 address should be specified.

### leader
By default, Kilo creates a network mesh at the data-center granularity.
This means that one leader node is selected from each location to be an edge server and act as the gateway to other locations; the network topology will be a full mesh between leaders.
Kilo automatically selects the leader for each location in a stable and deterministic manner to avoid churn in the network configuration, while giving preference to nodes that are known to have public IP addresses.
In some situations it may be desirable to manually select the leader for a location, for example:
 * _firewall_: Kilo requires an open UDP port, which defaults to 51820, to communicate between locations; if only one node is configured to have that port open, then that node should be given the leader annotation;
 * _bandwidth_: if certain nodes in the cluster have a higher bandwidth or lower latency Internet connection, then those nodes should be given the leader annotation.

_Note_: multiple nodes within a single location can be given the leader annotation; in this case, Kilo will select one leader from the set of annotated nodes. 

### location
Kilo allows nodes in different logical or physical locations to route packets to one-another.
In order to know what connections to create, Kilo needs to know which nodes are in each location.
Kilo will try to infer each node's location from the [failure-domain.beta.kubernetes.io/region](https://kubernetes.io/docs/reference/kubernetes-api/labels-annotations-taints/#failure-domain-beta-kubernetes-io-region) node label.
If the label is not present for a node, for example if running a bare-metal cluster or on an unsupported cloud provider, then the location annotation should be specified.

_Note_: all nodes without a defined location will be considered to be in the default location `""`.
