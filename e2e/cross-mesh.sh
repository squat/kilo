#!/usr/bin/env bash
# shellcheck disable=SC1091
. lib.sh

# This suite exercises --mesh-granularity=cross on the bridge-CNI test
# cluster. Cross drops the WireGuard tunnel between nodes that share a
# location and expects the underlying CNI to handle intra-location
# traffic over its own overlay (e.g. Cilium VXLAN). The Kilo bridge CNI
# used by this kind cluster has no such overlay, so cross-location peer
# topology can be validated here but pod-to-pod connectivity cannot —
# that lives in the Cilium-CNI suite (e2e/cilium-cross-mesh.sh).

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

# Restore the cluster to a clean state for the suites that follow
# (multi-cluster.sh, handlers.sh, kgctl.sh) by removing the location
# annotations this suite added.
teardown_suite() {
	_kubectl annotate node "$KIND_CLUSTER-control-plane" kilo.squat.ai/location- 2>/dev/null || true
	_kubectl annotate node "$KIND_CLUSTER-worker"        kilo.squat.ai/location- 2>/dev/null || true
	_kubectl annotate node "$KIND_CLUSTER-worker2"       kilo.squat.ai/location- 2>/dev/null || true
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
