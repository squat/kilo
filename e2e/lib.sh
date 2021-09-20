#!/usr/bin/env bash
KUBECONFIG="kind.yaml"
KIND_CLUSTER="kind-cluster-kilo"
KIND_BINARY="${KIND_BINARY:-kind}"
KUBECTL_BINARY="${KUBECTL_BINARY:-kubectl}"
KGCTL_BINARY="${KGCTL_BINARY:-kgctl}"
KILO_IMAGE="${KILO_IMAGE:-squat/kilo}"

retry() {
	local COUNT="${1:-10}"
	local SLEEP="${2:-5}"
	local ERROR=$3
	[ -n "$ERROR" ] && ERROR="$ERROR "
	shift 3
	for c in $(seq 1 "$COUNT"); do
		if "$@"; then
			return 0
		else
			printf "%s(attempt %d/%d)\n" "$ERROR" "$c" "$COUNT" | color "$YELLOW" 1>&2
			if [ "$c" != "$COUNT" ]; then
				printf "retrying in %d seconds...\n" "$SLEEP" | color "$YELLOW" 1>&2
				sleep "$SLEEP"
			fi
		fi
	done
	return 1
}

_not() {
	if "$@"; then
		return 1
	fi
	return 0
}

# _kubectl is a helper that calls kubectl with the --kubeconfig flag.
_kubectl() {
	$KUBECTL_BINARY --kubeconfig="$KUBECONFIG" "$@"
}

# _kgctl is a helper that calls kgctl with the --kubeconfig flag.
_kgctl() {
	$KGCTL_BINARY --kubeconfig="$KUBECONFIG" "$@"
}

# _kind is a helper that calls kind with the --kubeconfig flag.
_kind() {
	$KIND_BINARY --kubeconfig="$KUBECONFIG" "$@"
}

# shellcheck disable=SC2120
build_kind_config() {
	local WORKER_COUNT="${1:-0}"
	export API_SERVER_PORT="${2:-6443}"
	export POD_SUBNET="${3:-10.42.0.0/16}"
	export SERVICE_SUBNET="${4:-10.43.0.0/16}"
	export WORKERS="" 
	local i=0
	while [ "$i" -lt "$WORKER_COUNT" ]; do
		WORKERS="$(printf "%s\n- role: worker" "$WORKERS")"
		((i++))
	done
	envsubst < ./kind-config.yaml
	unset API_SERVER_PORT POD_SUBNET SERVICE_SUBNET WORKERS
}

create_interface() {
	docker run -d --name="$1" --rm --network=host --cap-add=NET_ADMIN --device=/dev/net/tun -v /var/run/wireguard:/var/run/wireguard -e WG_LOG_LEVEL=debug leonnicolas/boringtun --foreground --disable-drop-privileges true "$1"
}

delete_interface() {
	docker rm --force "$1"
}

create_peer() {
	cat <<EOF | _kubectl apply -f -
apiVersion: kilo.squat.ai/v1alpha1
kind: Peer
metadata:
  name: $1
spec:
  allowedIPs:
  - $2
  persistentKeepalive: $3
  publicKey: $4
EOF
}

delete_peer() {
	_kubectl delete peer "$1"
}

is_ready() {
	for pod in $(_kubectl -n "$1" get pods -o name -l "$2"); do
		if ! _kubectl -n "$1" get "$pod" | tail -n 1 | grep -q Running; then
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
	retry 30 5 "some $2 pods are not ready yet" is_ready "$1" "$2"
}


# create_cluster launches a kind cluster and deploys Kilo, Adjacency, and a helper with curl.
create_cluster() {
	# shellcheck disable=SC2119
	local CONFIG="${1:-$(build_kind_config)}"
	_kind delete clusters $KIND_CLUSTER > /dev/null
	# Create the kind cluster.
	_kind create cluster --name $KIND_CLUSTER --config <(echo "$CONFIG")
	# Load the Kilo image into kind.
	docker tag "$KILO_IMAGE" squat/kilo:test
	# This command does not accept the --kubeconfig flag, so call the command directly.
	$KIND_BINARY load docker-image squat/kilo:test --name $KIND_CLUSTER
	# Create the kubeconfig secret.
	_kubectl create secret generic kubeconfig --from-file=kubeconfig="$KUBECONFIG" -n kube-system
	# Apply Kilo the the cluster.
	_kubectl apply -f ../manifests/crds.yaml
	_kubectl apply -f kilo-kind-userspace.yaml
	block_until_ready_by_name kube-system kilo-userspace 
	_kubectl wait nodes --all --for=condition=Ready
	# Wait for CoreDNS.
	block_until_ready kube_system k8s-app=kube-dns
	# Ensure the curl helper is not scheduled on a control-plane node.
	_kubectl apply -f helper-curl.yaml
	block_until_ready_by_name default curl
	_kubectl taint node $KIND_CLUSTER-control-plane node-role.kubernetes.io/master:NoSchedule-
	_kubectl apply -f https://raw.githubusercontent.com/kilo-io/adjacency/main/example.yaml
	block_until_ready_by_name default adjacency
}

delete_cluster () {
	_kind delete clusters $KIND_CLUSTER
}

curl_pod() {
	_kubectl get pods -l app.kubernetes.io/name=curl -o name | xargs -I{} "$KUBECTL_BINARY" --kubeconfig="$KUBECONFIG" exec {} -- /usr/bin/curl "$@"
}

check_ping() {
	local LOCAL
	while [ $# -gt 0 ]; do
		case $1 in
			--local)
			LOCAL=true
			;;
		esac
		shift
	done

	for ip in $(_kubectl get pods -l app.kubernetes.io/name=adjacency -o jsonpath='{.items[*].status.podIP}'); do
		if [ -n "$LOCAL" ]; then
			ping=$(curl -m 1 -s http://"$ip":8080/ping)
		else
			ping=$(curl_pod -m 1 -s http://"$ip":8080/ping)
		fi
		if [ "$ping" = "pong" ]; then
			echo "successfully pinged $ip"
		else
			printf 'failed to ping %s; expected "pong" but got "%s"\n' "$ip" "$ping"
			return 1
		fi
	done
	return 0
}

check_adjacent() {
	curl_pod adjacency:8080/?format=fancy
	[ "$(curl_pod -m 1 -s adjacency:8080/?format=json | jq '.[].latencies[].ok' | grep -c true)" -eq $(($1*$1)) ]
}

check_peer() {
	local INTERFACE=$1
	local PEER=$2
	local ALLOWED_IP=$3
	local GRANULARITY=$4
	create_interface "$INTERFACE"
	docker run --rm leonnicolas/wg-tools wg genkey > "$INTERFACE"
	assert "create_peer $PEER $ALLOWED_IP 10 $(docker run --rm --entrypoint=/bin/sh -v "$PWD/$INTERFACE":/key leonnicolas/wg-tools -c 'cat /key | wg pubkey')" "should be able to create Peer"
	assert "_kgctl showconf peer $PEER --mesh-granularity=$GRANULARITY > $PEER.ini" "should be able to get Peer configuration"
	assert "docker run --rm --network=host --cap-add=NET_ADMIN --entrypoint=/usr/bin/wg -v /var/run/wireguard:/var/run/wireguard -v $PWD/$PEER.ini:/peer.ini leonnicolas/wg-tools setconf $INTERFACE /peer.ini" "should be able to apply configuration from kgctl"
	docker run --rm --network=host --cap-add=NET_ADMIN --entrypoint=/usr/bin/wg -v /var/run/wireguard:/var/run/wireguard -v "$PWD/$INTERFACE":/key leonnicolas/wg-tools set "$INTERFACE" private-key /key
	docker run --rm --network=host --cap-add=NET_ADMIN --entrypoint=/sbin/ip leonnicolas/wg-tools address add "$ALLOWED_IP" dev "$INTERFACE"
	docker run --rm --network=host --cap-add=NET_ADMIN --entrypoint=/sbin/ip leonnicolas/wg-tools link set "$INTERFACE" up
	docker run --rm --network=host --cap-add=NET_ADMIN --entrypoint=/sbin/ip leonnicolas/wg-tools route add 10.42/16 dev "$INTERFACE"
	assert "retry 10 5 '' check_ping --local" "should be able to ping Pods from host"
	assert_equals "$(_kgctl showconf peer "$PEER")" "$(_kgctl showconf peer "$PEER" --mesh-granularity="$GRANULARITY")" "kgctl should be able to auto detect the mesh granularity"
	rm "$INTERFACE" "$PEER".ini
	delete_peer "$PEER"
	delete_interface "$INTERFACE"
}
