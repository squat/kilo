#!/usr/bin/env bash
# shellcheck disable=SC1091
. lib.sh

# shellcheck disable=SC2153
KUBECONFIG2="$KUBECONFIG"2
# shellcheck disable=SC2153
KIND_CLUSTER2="$KIND_CLUSTER"2

setup_suite() {
	KUBECONFIG=$KUBECONFIG2 KIND_CLUSTER=$KIND_CLUSTER2 create_cluster "$(build_kind_config 1 6444 10.44.0.0/16 10.45.0.0/16)"
	# shellcheck disable=SC2016
	KUBECONFIG=$KUBECONFIG2 _kubectl patch ds -n kube-system kilo -p '{"spec": {"template":{"spec":{"containers":[{"name":"kilo","args":["--hostname=$(NODE_NAME)","--create-interface=false","--kubeconfig=/etc/kubernetes/kubeconfig","--mesh-granularity=full","--subnet=10.6.0.0/16"]}]}}}}'
	KUBECONFIG=$KUBECONFIG2 block_until_ready_by_name kube-system kilo-userspace 
	# Register the nodes in cluster1 as peers of cluster2.
	for n in $(_kubectl get no -o name | cut -d'/' -f2); do
		# Specify the service CIDR as an extra IP range that should be routable.
		$KGCTL_BINARY --kubeconfig "$KUBECONFIG" showconf node "$n" --as-peer -o yaml --allowed-ips 10.43.0.0/16 | $KUBECTL_BINARY --kubeconfig "$KUBECONFIG2" apply -f -
	done
	# Register the nodes in cluster2 as peers of cluster1.
	for n in $(KUBECONFIG=$KUBECONFIG2 _kubectl get no -o name | cut -d'/' -f2); do
		# Specify the service CIDR as an extra IP range that should be routable.
		$KGCTL_BINARY --kubeconfig "$KUBECONFIG2" showconf node "$n" --as-peer -o yaml --allowed-ips 10.45.0.0/16 | $KUBECTL_BINARY --kubeconfig "$KUBECONFIG" apply -f -
	done
}

test_multi_cluster_pod_connectivity() {
	for ip in $(KUBECONFIG=$KUBECONFIG2 _kubectl get pods -l app.kubernetes.io/name=adjacency -o jsonpath='{.items[*].status.podIP}'); do
		assert_equals pong "$(retry 10 5 "$ip is not yet routable" curl_pod -m 1 -s http://"$ip":8080/ping)" "should be able to make HTTP request from cluster 1 to Pod in cluster 2"
	done
	for ip in $(_kubectl get pods -l app.kubernetes.io/name=adjacency -o jsonpath='{.items[*].status.podIP}'); do
		assert_equals pong "$(KUBECONFIG="$KUBECONFIG2" retry 10 5 "$ip is not yet routable" curl_pod -m 1 -s http://"$ip":8080/ping)" "should be able to make HTTP request from cluster 2 to Pod in cluster 1"
	done
}

test_multi_cluster_service_connectivity() {
	# Mirror the Kubernetes API service from cluster1 into cluster2.
	cat <<EOF | $KUBECTL_BINARY --kubeconfig "$KUBECONFIG2" apply -f -
apiVersion: v1
kind: Service
metadata:
  name: mirrored-kubernetes
spec:
  ports:
    - port: 443
---
apiVersion: v1
kind: Endpoints
metadata:
    name: mirrored-kubernetes
subsets:
  - addresses:
      - ip: $(_kubectl get service kubernetes -o jsonpath='{.spec.clusterIP}') # The cluster IP of the Kubernetes API service on cluster1.
    ports:
      - port: 443
EOF
        assert_equals ok "$(KUBECONFIG="$KUBECONFIG2" retry 10 5 "service is not yet routable" curl_pod -m 1 -s -k https://mirrored-kubernetes/readyz)" "should be able to make HTTP request from cluster 2 to service in cluster 1"
}

teardown_suite () {
	if [ -n "$E2E_SKIP_TEARDOWN_ON_FAILURE" ]; then
		return
	fi
	# Remove the nodes in cluster2 as peers of cluster1.
	for n in $(KUBECONFIG=$KUBECONFIG2 _kubectl get no -o name | cut -d'/' -f2); do
		_kubectl delete peer "$n"
	done
	KUBECONFIG=$KUBECONFIG2 KIND_CLUSTER=$KIND_CLUSTER2 delete_cluster
}
