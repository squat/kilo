# Topology

Kilo allows the topology of the encrypted network to be customized.
A cluster administrator can specify whether the encrypted network should be a full mesh between every node, or if the mesh should be between distinct pools of nodes that communicate directly with one another.
This allows the encrypted network to serve several purposes, for example:
* on cloud providers with unsecured private networks, a full mesh can be created between the nodes to secure all cluster traffic;
* nodes running in different cloud providers can be joined into a single cluster by creating one link between the two clouds;
* more generally, links that are insecure can be encrypted while links that are secure can remain fast and unencapsulated.

## Logical Groups

By default, Kilo creates a mesh between the different logical locations in the cluster, e.g. data-centers, cloud providers, etc.
Kilo will try to infer the location of the node using the [failure-domain.beta.kubernetes.io/region](https://kubernetes.io/docs/reference/kubernetes-api/labels-annotations-taints/#failure-domain-beta-kubernetes-io-region) node label.
If this label is not set, then the [kilo.squat.ai/location](./annotations.md#location) node annotation can be used.

For example, in order to join nodes in Google Cloud and AWS into a single cluster, an administrator could use the following snippet could to annotate all nodes with `GCP` in the name:

```shell
for node in $(kubectl get nodes | grep -i gcp | awk '{print $1}'); do kubectl annotate node $node kilo.squat.ai/location="gcp"; done
```

In this case, Kilo would do the following:
* group all the nodes with the `GCP` annocation into a logical location;
* group all the nodes without an annotation would be grouped into default location; and
* elect a leader in each location and create a link between them.

Analyzing the cluster with `kgctl` would produce a result like:

```shell
kgctl graph | circo -Tsvg > cluster.svg
```

<img src="./graphs/location.svg">

## Full Mesh

Creating a full mesh is a logical reduction of the logical mesh where each node is in its own group.
Kilo provides a shortcut for this topology in the form of a command line flag: `--mesh-granularity=full`.
When the `full` mesh granularity is specified, Kilo configures the network so that all inter-node traffic is encrypted with WireGuard.

Analyzing the cluster with `kgctl` would produce a result like:

```shell
kgctl graph | circo -Tsvg > cluster.svg
```

<img src="./graphs/full-mesh.svg">

## Mixed 

The `kilo.squat.ai/location` annotation can be used to create cluster mixing some fully meshed nodes and some nodes grouped by logical location.
For example, if a cluster contained a set of nodes in Google cloud and a set of nodes with no secure private network, e.g. some bare metal nodes, then the nodes in Google Cloud could be placed in one logical group while the bare metal nodes could form a full mesh.

This could be accomplished by running:

```shell
for node in $(kubectl get nodes | grep -i gcp | awk '{print $1}'); do kubectl annotate node $node kilo.squat.ai/location="gcp"; done
for node in $(kubectl get nodes | tail -n +2 | grep -v gcp | awk '{print $1}'); do kubectl annotate node $node kilo.squat.ai/location="$node"; done
```

Analyzing the cluster with `kgctl` would produce a result like:

```shell
kgctl graph | circo -Tsvg > cluster.svg
```

<img src="./graphs/mixed.svg">

If the cluster also had nodes in AWS, then the following snippet could be used:

```shell
for node in $(kubectl get nodes | grep -i aws | awk '{print $1}'); do kubectl annotate node $node kilo.squat.ai/location="aws"; done
for node in $(kubectl get nodes | grep -i gcp | awk '{print $1}'); do kubectl annotate node $node kilo.squat.ai/location="gcp"; done
for node in $(kubectl get nodes | tail -n +2 | grep -v aws | grep -v gcp | awk '{print $1}'); do kubectl annotate node $node kilo.squat.ai/location="$node"; done
```

This would in turn produce a graph like:

```shell
kgctl graph | circo -Tsvg > cluster.svg
```

<img src="./graphs/complex.svg">
