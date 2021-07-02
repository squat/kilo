#!/usr/bin/env bash
# shellcheck disable=SC1091
. lib.sh

setup_suite() {
	# shellcheck disable=SC2016
	$KUBECTL_BINARY patch ds -n kube-system kilo -p '{"spec": {"template":{"spec":{"containers":[{"name":"kilo","args":["--hostname=$(NODE_NAME)","--create-interface=false","--kubeconfig=/etc/kubernetes/kubeconfig","--mesh-granularity=location"]}]}}}}'
	block_until_ready_by_name kube-system kilo-userspace 
	$KUBECTL_BINARY wait pod -l app.kubernetes.io/name=adjacency --for=condition=Ready --timeout 3m
}

test_location_mesh_connectivity() {
	assert "retry 30 5 '' check_ping" "should be able to ping all Pods"
	assert "retry 10 5 'the adjacency matrix is not complete yet' check_adjacent 12" "adjacency should return the right number of successful pings"
	echo "sleep for 30s (one reconciliation period) and try again..."
	sleep 30
	assert "retry 10 5 'the adjacency matrix is not complete yet' check_adjacent 12" "adjacency should return the right number of successful pings after reconciling"
}

test_location_mesh_peer() {
	check_peer wg1 e2e 10.5.0.1/32 location
}

test_mesh_granularity_auto_detect() {
	 assert_equals "$($KGCTL_BINARY graph)" "$($KGCTL_BINARY graph --mesh-granularity location)"
}
