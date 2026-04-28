#!/usr/bin/env bash
# shellcheck disable=SC1091
. lib.sh

setup_suite() {
	# Place control-plane and the first worker into one location, and the
	# second worker into another, so that "cross" produces tunnels only
	# between the two locations and not within a single location.
	_kubectl annotate node "$KIND_CLUSTER-control-plane" kilo.squat.ai/location=loc-a --overwrite
	_kubectl annotate node "$KIND_CLUSTER-worker"        kilo.squat.ai/location=loc-a --overwrite
	_kubectl annotate node "$KIND_CLUSTER-worker2"       kilo.squat.ai/location=loc-b --overwrite
	# shellcheck disable=SC2016
	_kubectl patch ds -n kube-system kilo -p '{"spec": {"template":{"spec":{"containers":[{"name":"kilo","args":["--hostname=$(NODE_NAME)","--create-interface=false","--kubeconfig=/etc/kubernetes/kubeconfig","--mesh-granularity=cross"]}]}}}}'
	block_until_ready_by_name kube-system kilo-userspace
}

test_cross_mesh_connectivity() {
	assert "retry 30 5 '' check_ping" "should be able to ping all Pods"
	assert "retry 10 5 'the adjacency matrix is not complete yet' check_adjacent 3" "adjacency should return the right number of successful pings"
	echo "sleep for 30s (one reconciliation period) and try again..."
	sleep 30
	assert "retry 10 5 'the adjacency matrix is not complete yet' check_adjacent 3" "adjacency should return the right number of successful pings after reconciling"
}

test_cross_mesh_peer() {
	check_peer wg99 e2e 10.5.0.1/32 cross
}

test_mesh_granularity_auto_detect() {
	assert_equals "$(_kgctl graph)" "$(_kgctl graph --mesh-granularity cross)"
}

# In "cross" granularity, every node in another location must appear as a
# WireGuard peer (direct tunnels across locations), while nodes in the same
# location must NOT appear as peers (intra-location traffic stays on the CNI).
# In "location" the same-location worker would not have any [Peer] entry at
# all (it is a non-leader); in "full" both same- and cross-location nodes
# would appear as peers. This sanity-checks that "cross" sits in between.
test_cross_peer_topology() {
	local CP_PEERS WORKER_PEERS WORKER2_PEERS
	CP_PEERS=$(_kgctl showconf node "$KIND_CLUSTER-control-plane" | grep -c '^\[Peer\]')
	WORKER_PEERS=$(_kgctl showconf node "$KIND_CLUSTER-worker"        | grep -c '^\[Peer\]')
	WORKER2_PEERS=$(_kgctl showconf node "$KIND_CLUSTER-worker2"      | grep -c '^\[Peer\]')
	# Each loc-a node should peer only with the single loc-b node.
	assert_equals "1" "$CP_PEERS"      "control-plane (loc-a) should have 1 peer (the loc-b node)"
	assert_equals "1" "$WORKER_PEERS"  "worker (loc-a) should have 1 peer (the loc-b node)"
	# The loc-b node should peer with both loc-a nodes.
	assert_equals "2" "$WORKER2_PEERS" "worker2 (loc-b) should have 2 peers (both loc-a nodes)"
}
