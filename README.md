<p align="center"><img src="./kilo.svg" width="150"></p>

# Kilo

Kilo is a multi-cloud network overlay built on WireGuard and designed for Kubernetes.

[![Build Status](https://travis-ci.org/squat/kilo.svg?branch=master)](https://travis-ci.org/squat/kilo)
[![Go Report Card](https://goreportcard.com/badge/github.com/squat/kilo)](https://goreportcard.com/report/github.com/squat/kilo)

## Overview

Kilo connects nodes in a cluster by providing an encrypted layer 3 network that can span across data centers and public clouds.
By allowing pools of nodes in different locations to communicate securely, Kilo enables the operation of multi-cloud clusters.
Kilo's design allows clients to VPN to a cluster in order to securely access services running on the cluster.
In addition to creating multi-cloud clusters, Kilo enables the creation of multi-cluster services, i.e. services that span across different Kubernetes clusters.

## How it works

Kilo uses [WireGuard](https://www.wireguard.com/), a performant and secure VPN, to create a mesh between the different nodes in a cluster.
The Kilo agent, `kg`, runs on every node in the cluster, setting up the public and private keys for the VPN as well as the necessary rules to route packets between locations.

Kilo can operate both as a complete, independent networking provider as well as an add-on complimenting the cluster-networking solution currently installed on a cluster.
This means that if a cluster uses, for example, Flannel for networking, Kilo can be installed on top to enable pools of nodes in different locations to join; Kilo will take care of the network between locations, while Flannel will take care of the network within locations.

## Installing on Kubernetes

Kilo can be installed on any Kubernetes cluster either pre- or post-bring-up.

### Step 1: install WireGuard

Kilo requires the WireGuard kernel module on all nodes in the cluster.
For most Linux distributions, this can be installed using the system package manager.
For Container Linux, WireGuard can be easily installed using a DaemonSet:

```shell
kubectl apply -f https://raw.githubusercontent.com/squat/modulus/master/wireguard/daemonset.yaml
```

### Step 2: open WireGuard port

The nodes in the mesh will require an open UDP port in order to communicate.
By default, Kilo uses UDP port 51820.

### Step 3: specify topology

By default, Kilo creates a mesh between the different logical locations in the cluster, e.g. data-centers, cloud providers, etc.
For this, Kilo needs to know which groups of nodes are in each location.
If the cluster does not automatically set the [topology.kubernetes.io/region](https://kubernetes.io/docs/reference/kubernetes-api/labels-annotations-taints/#topologykubernetesioregion) node label, then the [kilo.squat.ai/location](./docs/annotations.md#location) annotation can be used.
For example, the following snippet could be used to annotate all nodes with `GCP` in the name:

```shell
for node in $(kubectl get nodes | grep -i gcp | awk '{print $1}'); do kubectl annotate node $node kilo.squat.ai/location="gcp"; done
```

Kilo allows the topology of the encrypted network to be completely customized.
[See the topology docs for more details](./docs/topology.md).

### Step 4: ensure nodes have public IP

At least one node in each location must have a public IP address.
If the public IP address is not automatically configured on the node's Ethernet device, it can be manually specified using the [kilo.squat.ai/force-external-ip](./docs/annotations.md#force-external-ip) annotation.

### Step 5: install Kilo!

Kilo can be installed by deploying a DaemonSet to the cluster.

To run Kilo on kubeadm:

```shell
kubectl apply -f https://raw.githubusercontent.com/squat/kilo/master/manifests/kilo-kubeadm.yaml
```

To run Kilo on bootkube:

```shell
kubectl apply -f https://raw.githubusercontent.com/squat/kilo/master/manifests/kilo-bootkube.yaml
```

To run Kilo on Typhoon:

```shell
kubectl apply -f https://raw.githubusercontent.com/squat/kilo/master/manifests/kilo-typhoon.yaml
```

To run Kilo on k3s:

```shell
kubectl apply -f https://raw.githubusercontent.com/squat/kilo/master/manifests/kilo-k3s.yaml
```

## Add-on Mode

Administrators of existing clusters who do not want to swap out the existing networking solution can run Kilo in add-on mode.
In this mode, Kilo will add advanced features to the cluster, such as VPN and multi-cluster services, while delegating CNI management and local networking to the cluster's current networking provider.
Kilo currently supports running on top of Flannel.

For example, to run Kilo on a Typhoon cluster running Flannel:

```shell
kubectl apply -f https://raw.githubusercontent.com/squat/kilo/master/manifests/kilo-typhoon-flannel.yaml
```

[See the manifests directory for more examples](./manifests).

## VPN

Kilo also enables peers outside of a Kubernetes cluster to connect to the VPN, allowing cluster applications to securely access external services and permitting developers and support to securely debug cluster resources.
In order to declare a peer, start by defining a Kilo peer resource:

```shell
cat <<'EOF' | kubectl apply -f -
apiVersion: kilo.squat.ai/v1alpha1
kind: Peer
metadata:
  name: squat
spec:
  allowedIPs:
  - 10.5.0.1/32
  publicKey: GY5aT1N9dTR/nJnT1N2f4ClZWVj0jOAld0r8ysWLyjg=
  persistentKeepalive: 10
EOF
```

This configuration can then be applied to a local WireGuard interface, e.g. `wg0`, to give it access to the cluster with the help of the `kgctl` tool:

```shell
kgctl showconf peer squat > peer.ini
sudo wg setconf wg0 peer.ini
```

[See the VPN docs for more details](./docs/vpn.md).

In case you want to only run Kilo as VPN server, [see the VPN-only walkthrough](./docs/vpn-only.md)
for details.

## Multi-cluster Services

A logical application of Kilo's VPN is to connect two different Kubernetes clusters.
This allows workloads running in one cluster to access services running in another.
For example, if `cluster1` is running a Kubernetes Service that we need to access from Pods running in `cluster2`, we could do the following:

```shell
# Register the nodes in cluster1 as peers of cluster2.
for n in $(kubectl --kubeconfig $KUBECONFIG1 get no -o name | cut -d'/' -f2); do
    kgctl --kubeconfig $KUBECONFIG1 showconf node $n --as-peer -o yaml --allowed-ips $SERVICECIDR1 | kubectl --kubeconfig $KUBECONFIG2 apply -f -
done
# Register the nodes in cluster2 as peers of cluster1.
for n in $(kubectl --kubeconfig $KUBECONFIG2 get no -o name | cut -d'/' -f2); do
    kgctl --kubeconfig $KUBECONFIG2 showconf node $n --as-peer -o yaml --allowed-ips $SERVICECIDR2 | kubectl --kubeconfig $KUBECONFIG1 apply -f -
done
# Create a Service in cluster2 to mirror the Service in cluster1.
cat <<'EOF' | kubectl --kubeconfig $KUBECONFIG2 apply -f -
apiVersion: v1
kind: Service
metadata:
  name: important-service
spec:
  ports:
    - port: 80
---
apiVersion: v1
kind: Endpoints
metadata:
    name: important-service
subsets:
  - addresses:
      - ip: $CLUSTERIP # The cluster IP of the important service on cluster1.
    ports:
      - port: 80
EOF
```

Now, `important-service` can be used on `cluster2` just like any other Kubernetes Service.

[See the multi-cluster services docs for more details](./docs/multi-cluster-services.md).

## Analysis

The topology and configuration of a Kilo network can be analyzed using the `kgctl` binary.
For example, the `graph` command can be used to generate a graph of the network in Graphviz format:

```shell
kgctl graph | circo -Tsvg > cluster.svg
```

<img src="./docs/graphs/location.svg">
