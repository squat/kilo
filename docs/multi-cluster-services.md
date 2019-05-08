# Multi-cluster Services

Just as Kilo can connect a Kubernetes cluster to external services over WireGuard, it can connect multiple independent Kubernetes clusters.
This enables clusters to provide services to other clusters over a secure connection.
For example, a cluster on AWS with access to GPUs could run a machine learning service that could be consumed by workloads running in a another location, e.g. an on-prem cluster without GPUs.
Unlike services exposed via Ingresses or NodePort Services, multi-cluster services can remain private and internal to the clusters.

*Note*: clusters connected with Kilo must have non-overlapping pod and service CIDRs.

Consider two clusters, `cluster1` with:
* kubeconfig: `KUBECONFIG1`
* pod CIDR: `$PODCIDR1`
* service CIDR: `$SERVICECIDR1`
* a node named: `$NODE1`

and `cluster2` with:
* kubeconfig: `KUBECONFIG2`
* pod CIDR: `$PODCIDR2`
* service CIDR: `$SERVICECIDR2`
* a node named: `$NODE2`

In order to give `cluster2` access to a service running on `cluster1`, start by peering the nodes:

```shell
# Register cluster1 as a peer of cluster2.
kgctl --kubeconfig $KUBECONFIG1 showconf node $NODE1 --as-peer -o yaml --allowed-ips $PODCIDR1,$SERVICECIDR1 | kubectl --kubeconfig KUBECONFIG2 apply -f -
# Register cluster2 as a peer of cluster1.
kgctl --kubeconfig $KUBECONFIG2 showconf node $NODE2 --as-peer -o yaml --allowed-ips $PODCIDR2,$SERVICECIDR2 | kubectl --kubeconfig KUBECONFIG1 apply -f -
```

Now, `cluster2` has access to Pods and Services on `cluster1`, and vice-versa.
However, as it stands the external Services can only be accessed by using their clusterIPs directly; in other words, they are not Kubernetes-native.
We can change that by creating a Kubernetes Service in `cluster2` to mirror the Service in `cluster1`:

```shell
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
