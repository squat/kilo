#!/usr/bin/env bash
# shellcheck disable=SC1091
. lib.sh

setup_suite() {
	# shellcheck disable=SC2016
	block_until_ready_by_name kube-system kilo-userspace 
	_kubectl wait pod -l app.kubernetes.io/name=adjacency --for=condition=Ready --timeout 3m
}

test_connect() {
	local PEER=test
	local ALLOWED_IP=10.5.0.1/32
        docker run -d --name="$PEER" --rm --network=host --cap-add=NET_ADMIN -v "$KGCTL_BINARY":/kgctl -v "$PWD/$KUBECONFIG":/kubeconfig --entrypoint=/kgctl alpine --kubeconfig /kubeconfig connect "$PEER" --allowed-ip "$ALLOWED_IP"
	assert "retry 10 5 '' check_ping --local" "should be able to ping Pods from host"
        docker stop "$PEER"

	local PEER=test-hostname
	local ALLOWED_IP=10.5.0.1/32
        docker run -d --name="$PEER" --rm --network=host --cap-add=NET_ADMIN -v "$KGCTL_BINARY":/kgctl -v "$PWD/$KUBECONFIG":/kubeconfig --entrypoint=/kgctl alpine --kubeconfig /kubeconfig connect --allowed-ip "$ALLOWED_IP"
	assert "retry 10 5 '' check_ping --local" "should be able to ping Pods from host using auto-discovered name"
        docker stop "$PEER"
}
