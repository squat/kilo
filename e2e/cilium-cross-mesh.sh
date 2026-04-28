#!/usr/bin/env bash
# shellcheck disable=SC1091
. lib.sh

# Cilium-CNI counterpart of e2e/cross-mesh.sh. The Kilo DaemonSet is the
# one applied by create_cilium_cluster (kilo-kind-cilium.yaml), which
# already runs Kilo with --cni=false --compatibility=cilium. This suite
# only annotates locations and switches granularity to "cross".
setup_suite() {
	_kubectl annotate node "$KIND_CLUSTER-control-plane" kilo.squat.ai/location=loc-a --overwrite
	_kubectl annotate node "$KIND_CLUSTER-worker"        kilo.squat.ai/location=loc-a --overwrite
	_kubectl annotate node "$KIND_CLUSTER-worker2"       kilo.squat.ai/location=loc-b --overwrite
	# shellcheck disable=SC2016
	_kubectl patch ds -n kube-system kilo -p '{"spec":{"template":{"spec":{"containers":[{"name":"kilo","args":["--hostname=$(NODE_NAME)","--create-interface=false","--cni=false","--compatibility=cilium","--mesh-granularity=cross","--kubeconfig=/etc/kubernetes/kubeconfig","--internal-cidr=$(NODE_IP)/32"]}]}}}}'
	block_until_ready_by_name kube-system kilo-userspace
}

test_cilium_cross_mesh_connectivity() {
	assert "retry 30 5 '' check_ping" "should be able to ping all Pods over Cilium VXLAN + Kilo cross mesh"
	assert "retry 10 5 'the adjacency matrix is not complete yet' check_adjacent 3" "adjacency should return the right number of successful pings"
	echo "sleep for 30s (one reconciliation period) and try again..."
	sleep 30
	assert "retry 10 5 'the adjacency matrix is not complete yet' check_adjacent 3" "adjacency should return the right number of successful pings after reconciling"
}

test_cilium_cross_peer_topology() {
	local CP_PEERS WORKER_PEERS WORKER2_PEERS
	CP_PEERS=$(_kgctl showconf node "$KIND_CLUSTER-control-plane" | grep -c '^\[Peer\]')
	WORKER_PEERS=$(_kgctl showconf node "$KIND_CLUSTER-worker"        | grep -c '^\[Peer\]')
	WORKER2_PEERS=$(_kgctl showconf node "$KIND_CLUSTER-worker2"      | grep -c '^\[Peer\]')
	assert_equals "1" "$CP_PEERS"      "control-plane (loc-a) should have 1 peer (the loc-b node)"
	assert_equals "1" "$WORKER_PEERS"  "worker (loc-a) should have 1 peer (the loc-b node)"
	assert_equals "2" "$WORKER2_PEERS" "worker2 (loc-b) should have 2 peers (both loc-a nodes)"
}
