# Userspace WireGuard

It is possible to use a userspace implementation of WireGuard with Kilo.
This can make sense if

* not all nodes in the cluster have WireGuard installed
* no one wants to install the DKMS WireGuard package on these nodes

## Homogeneous Cluster

With a homogeneous cluster (no node has the WireGuard kernel module), you can run a userspace WireGuard implementation as a DaemonSet.
This will create a WireGuard interface and Kilo will configure it.
In order to avoid a race condition, `kg` needs to be passed the `--create-interface=false` flag. 

An example configuration for a k3s cluster with [boringtun](https://github.com/cloudflare/boringtun) can be applied with 

```shell
kubectl apply -f https://raw.githubusercontent.com/squat/Kilo/master/manifests/kilo-k3s-userspace.yaml
```

__Note:__ even if some nodes have the WireGuard kernel module, this will still use the userspace implementation of WireGuard.

## Heterogeneous Cluster

If you have a heterogeneous cluster (some nodes are missing the WireGuard kernel module) and you wish to use the kernel module, if available, you can apply this configuration to a k3s cluster:

```shell
kubectl apply -f https://raw.githubusercontent.com/squat/Kilo/master/manifests/kilo-k3s-userspace-heterogeneous.yaml
```

This config will apply [nkml](https://github.com/leonnicolas/nkml) as a DaemonSet to label all nodes according to the presence of the WireGuard kernel module.
It will apply two different DaemonSets with Kilo: `kilo` without userspace WireGuard and `kilo-userspace` with boringtun as a sidecar.
Because Kilo is dependant on nkml, it needs to run on the host network and needs a kubeconfig to be able to update the labels.
