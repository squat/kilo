# Multi-cluster Services

Just as Kilo can connect a Kubernetes cluster to external services over WireGuard, it can connect multiple independent Kubernetes clusters.
This enables clusters to provide services to other clusters over a secure connection.
For example, a cluster on AWS with access to GPUs could run a machine learning service that could be consumed by workloads running in a another location, e.g. an on-prem cluster without GPUs.
Unlike services exposed via Ingresses or NodePort Services, multi-cluster services can remain private and internal to the clusters.

*Note*: in order for connected clusters to be fully routable, the allowed IPs that they declare must be non-overlapping, i.e. the Kilo, pod, and service CIDRs.

## Getting Started

Consider two clusters, `cluster1` with:
* kubeconfig: `KUBECONFIG1`; and
* service CIDR: `$SERVICECIDR1`

and `cluster2` with:
* kubeconfig: `KUBECONFIG2`
* service CIDR: `$SERVICECIDR2`; and

In order to give `cluster2` access to a service running on `cluster1`, start by peering the nodes:

```shell
# Register the nodes in cluster1 as peers of cluster2.
for n in $(kubectl --kubeconfig $KUBECONFIG1 get no -o name | cut -d'/' -f2); do
    # Specify the service CIDR as an extra IP range that should be routable.
    kgctl --kubeconfig $KUBECONFIG1 showconf node $n --as-peer -o yaml --allowed-ips $SERVICECIDR1 | kubectl --kubeconfig KUBECONFIG2 apply -f -
done
# Register the nodes in cluster2 as peers of cluster1.
for n in $(kubectl --kubeconfig $KUBECONFIG2 get no -o name | cut -d'/' -f2); do
    # Specify the service CIDR as an extra IP range that should be routable.
    kgctl --kubeconfig $KUBECONFIG2 showconf node $n --as-peer -o yaml --allowed-ips $SERVICECIDR2 | kubectl --kubeconfig KUBECONFIG1 apply -f -
done
```

Now, Pods on `cluster1` can ping, cURL, or otherwise make requests against Pods and Services in `cluster2` and vice-versa.

## Mirroring Services

At this point, Kilo has created a fully routable network between the two clusters.
However, as it stands the external Services can only be accessed by using their clusterIPs directly.
For example, a Pod in `cluster2` would need to use the URL `http://$CLUSTERIP_FROM_CLUSTER1` to make an HTTP request against a Service running in `cluster1`.
In other words, the Services are not yet Kubernetes-native.

We can easily change that by creating a Kubernetes Service in `cluster2` to mirror the Service in `cluster1`:

```shell
cat <<EOF | kubectl --kubeconfig $KUBECONFIG2 apply -f -
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
      - ip: $(kubectl --kubeconfig $KUBECONFIG1 get service important-service -o jsonpath='{.spec.clusterIP}') # The cluster IP of the important service on cluster1.
    ports:
      - port: 80
EOF
```

Now, `important-service` can be used and discovered on `cluster2` just like any other Kubernetes Service.
That means that a Pod in `cluster2` could directly use the Kubernetes DNS name for the Service when making HTTP requests, for example: `http://important-service.default.svc.cluster.local`.

Notice that this mirroring is ad-hoc, requiring manual administration of each Service.
This process can be fully automated using [Service-Reflector](https://github.com/squat/service-reflector) to discover and mirror Kubernetes Services between connected clusters.
