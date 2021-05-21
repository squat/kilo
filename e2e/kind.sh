#!/usr/bin/env bash
# shellcheck disable=SC2034
KUBECONFIG="kind.yaml"
KIND_CLUSTER="kind-cluster-kilo"
KIND_BINARY="${KIND_BINARY:-kind}"
KUBECTL_BINARY="${KUBECTL_BINARY:-kubectl}"
KILO_IMAGE="${KILO_IMAGE:-squat/kilo}"

is_ready() {
	for pod in $($KUBECTL_BINARY -n "$1" get pods -o name -l "$2"); do
		if ! $KUBECTL_BINARY -n "$1" get "$pod" | tail -n 1 | grep -q  Running; then
			return 1;
		fi
	done
	return 0
}

# Returns non zero if one pod of the given name in the given namespace is not ready.
block_until_ready_by_name() {
	block_until_ready "$1" "app.kubernetes.io/name=$2"
}

# Blocks until all pods of a deployment are ready.
block_until_ready() {
	# Just abort after 150s
	for c in {1..30}; do
		if is_ready "$1" "$2"; then
                        break
                else
			echo "some $2 pods are not ready, yet. Retries=$c/30"
			sleep 5
		fi
	done
	return 0
}

# Block waits until pods are ready. When patching pods, it is not very reliable because sometimes it checkts the state of old pods.
block() {
	$KUBECTL_BINARY -n "$1" wait -l "app.kubernetes.io/name=$2" pod  --for=condition=Ready
}

# Set up the kind cluster and deploy Kilo, Adjacency and a helper with curl.
setup_suite() {
	$KIND_BINARY delete clusters $KIND_CLUSTER > /dev/null
	# Create the kind cluster.
	$KIND_BINARY create cluster --name $KIND_CLUSTER --config ./kind-config.yaml
	# Load the Kilo image into kind.
	docker tag "$KILO_IMAGE" squat/kilo:test
	$KIND_BINARY load docker-image squat/kilo:test --name $KIND_CLUSTER
	# Apply Kilo the the cluster.
	$KUBECTL_BINARY apply -f kilo-kind-userspace.yaml
	block_until_ready_by_name kube-system kilo-userspace 
	$KUBECTL_BINARY wait nodes --all --for=condition=Ready
	# wait for coredns
	block_until_ready kube_system k8s-app=kube-dns
	$KUBECTL_BINARY taint node $KIND_CLUSTER-control-plane node-role.kubernetes.io/master:NoSchedule-
	$KUBECTL_BINARY apply -f https://raw.githubusercontent.com/heptoprint/adjacency/master/example.yaml
	$KUBECTL_BINARY apply -f helper-curl.yaml
	block_until_ready_by_name adjacency adjacency
	block_until_ready_by_name default curl
}

block_until_ping() {
	for c in {1..30}; do
		keepgoing=1
		# Block until all IP addresses of the adjacency pods are reached.
		for ip in $($KUBECTL_BINARY get pods -l app.kubernetes.io/name=adjacency -o jsonpath='{.items[*].status.podIP}'); do
			ping=$($KUBECTL_BINARY get pods -l app.kubernetes.io/name=curl -o name | xargs -I{} "$KUBECTL_BINARY" exec {} -- /bin/sh -c "curl -s http://$ip:8080/ping")
			if [[ $ping == "pong" ]]; then
				echo "successfully pinged $ip"
				keepgoing=0
			else
				keepgoing=1
				echo "expected \"pong\" got \"$ping\""
				break
			fi
		done
		if [[ $keepgoing == 0 ]]; then
			break
		else
			sleep 5
		fi
	done
}

check_adjacent() {
	echo
	$KUBECTL_BINARY get pods -l app.kubernetes.io/name=curl -o name | xargs -I{} "$KUBECTL_BINARY" exec {} -- /bin/sh -c 'curl -s adjacency:8080/?format=fancy'
	assert_equals "12" \
		"$($KUBECTL_BINARY get pods -l app.kubernetes.io/name=curl -o name | xargs -I{} "$KUBECTL_BINARY" exec {} -- /bin/sh -c 'curl -s adjacency:8080/?format=json' | jq | grep -c true)" \
		"Adjacency returned the wrong number of successful pings"
	echo "sleep for 30s (one reconciliation period) and try again..."
	sleep 30
	echo
	$KUBECTL_BINARY get pods -l app.kubernetes.io/name=curl -o name | xargs -I{} "$KUBECTL_BINARY" exec {} -- /bin/sh -c 'curl -s adjacency:8080/?format=fancy'
	assert_equals "12" \
		"$($KUBECTL_BINARY get pods -l app.kubernetes.io/name=curl -o name | xargs -I{} "$KUBECTL_BINARY" exec {} -- /bin/sh -c 'curl -s adjacency:8080/?format=json' | jq | grep -c true)" \
		 "Adjacency returned the wrong number of successful pings"
}

test_locationmesh() {
	# shellcheck disable=SC2016
	$KUBECTL_BINARY patch ds -n kube-system kilo -p '{"spec": {"template":{"spec":{"containers":[{"name":"kilo","args":["--hostname=$(NODE_NAME)","--create-interface=false","--mesh-granularity=location"]}]}}}}'
	sleep 5
	block_until_ready_by_name kube-system kilo-userspace 
	block_until_ping
	$KUBECTL_BINARY wait pod -l app.kubernetes.io/name=adjacency --for=condition=Ready --timeout 3m
	sleep 5
	check_adjacent
}

test_fullmesh() {
	# shellcheck disable=SC2016
	$KUBECTL_BINARY patch ds -n kube-system kilo -p '{"spec": {"template":{"spec":{"containers":[{"name":"kilo","args":["--hostname=$(NODE_NAME)","--create-interface=false","--mesh-granularity=full"]}]}}}}'
	sleep 5
	block_until_ready_by_name kube-system kilo-userspace 
	block_until_ping
	$KUBECTL_BINARY wait pod -l app.kubernetes.io/name=adjacency --for=condition=Ready --timeout 3m
	sleep 5
	check_adjacent
}

teardown_suite () {
	$KIND_BINARY delete clusters $KIND_CLUSTER
}
