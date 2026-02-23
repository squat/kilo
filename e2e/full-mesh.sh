#!/usr/bin/env bash
# shellcheck disable=SC1091
. lib.sh

setup_suite() {
	# shellcheck disable=SC2016
	_kubectl patch ds -n kube-system kilo -p '{"spec": {"template":{"spec":{"containers":[{"name":"kilo","args":["--hostname=$(NODE_NAME)","--create-interface=false","--kubeconfig=/etc/kubernetes/kubeconfig","--mesh-granularity=full"]}]}}}}'
	block_until_ready_by_name kube-system kilo-userspace 
}

test_full_mesh_connectivity() {
	assert "retry 30 5 '' check_ping" "should be able to ping all Pods"
	assert "retry 10 5 'the adjacency matrix is not complete yet' check_adjacent 3" "adjacency should return the right number of successful pings"
	echo "sleep for 30s (one reconciliation period) and try again..."
	sleep 30
	assert "retry 10 5 'the adjacency matrix is not complete yet' check_adjacent 3" "adjacency should return the right number of successful pings after reconciling"
}

test_full_mesh_peer() {
	check_peer wg99 e2e 10.5.0.1/32 full
}

test_full_mesh_allowed_location_ips() {
	docker exec kind-cluster-kilo-control-plane ip address add 10.6.0.1/32 dev eth0
	_kubectl annotate node kind-cluster-kilo-control-plane kilo.squat.ai/allowed-location-ips=10.6.0.1/32
	assert_equals Unauthorized "$(retry 10 5 'IP is not yet routable' curl_pod -m 1 -s -k https://10.6.0.1:10250/healthz)" "should be able to make HTTP request to allowed location IP"
	_kubectl annotate node kind-cluster-kilo-control-plane kilo.squat.ai/allowed-location-ips-
	assert "retry 10 5 'IP is still routable' _not curl_pod -m 1 -s -k https://10.6.0.1:10250/healthz" "should not be able to make HTTP request to allowed location IP"
	docker exec kind-cluster-kilo-control-plane ip address delete 10.6.0.1/32 dev eth0
}

test_reject_peer_empty_allowed_ips() {
	assert_fail "create_peer e2e '' 0 foo" "should not be able to create Peer with empty allowed IPs"
}

test_reject_peer_empty_public_key() {
	assert_fail "create_peer e2e 10.5.0.1/32 0 ''" "should not be able to create Peer with empty public key"
}

test_mesh_granularity_auto_detect() {
	assert_equals "$(_kgctl graph)" "$(_kgctl graph --mesh-granularity full)"
}
