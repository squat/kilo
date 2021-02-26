# Userspace WireGuard

It is possible to use a userspace implementation of WireGuard with Kilo.
This can make sense in cases where

* not all nodes in a cluster have WireGuard installed; or
* nodes are effectively immutable and kernel modules cannot be installed.

## Homogeneous Clusters

In a homogeneous cluster where no node has the WireGuard kernel module, a userspace WireGuard implementation can be made available by deploying a DaemonSet.
This DaemonSet creates a WireGuard interface that Kilo will manage.
In order to avoid race conditions, `kg` needs to be passed the `--create-interface=false` flag. 

An example configuration for a k3s cluster with [boringtun](https://github.com/cloudflare/boringtun) can be applied with:

```shell
kubectl apply -f https://raw.githubusercontent.com/squat/kilo/main/manifests/kilo-k3s-userspace.yaml
```

__Note:__ even if some nodes have the WireGuard kernel module, this configuration will cause all nodes to use the userspace implementation of WireGuard.

## Heterogeneous Clusters

In a heterogeneous cluster where some nodes are missing the WireGuard kernel module, a userspace WireGuard implementation can be provided only to the nodes that need it while enabling the other nodes to leverage WireGuard via the kernel module.
An example of such a configuration for a k3s cluster can by applied with:

```shell
kubectl apply -f https://raw.githubusercontent.com/squat/kilo/main/manifests/kilo-k3s-userspace-heterogeneous.yaml
```

This configuration will deploy [nkml](https://github.com/leonnicolas/nkml) as a DaemonSet to label all nodes according to the presence of the WireGuard kernel module.
It will also create two different DaemonSets with Kilo: `kilo` without userspace WireGuard and `kilo-userspace` with boringtun as a sidecar.
__Note:__ because Kilo is dependant on nkml, nkml must be run on the host network before CNI is available and requires a kubeconfig in order to access the Kubernetes API.
