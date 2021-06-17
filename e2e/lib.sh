#!/usr/bin/env bash
export KUBECONFIG="kind.yaml"
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
			printf "%s(attempt %d/%d)\n" "$ERROR" "$c" "$COUNT" | color "$YELLOW"
			if [ "$c" != "$COUNT" ]; then
				printf "retrying in %d seconds...\n" "$SLEEP" | color "$YELLOW"
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

create_interface() {
	docker run -d --name="$1" --rm --network=host --cap-add=NET_ADMIN --device=/dev/net/tun -v /var/run/wireguard:/var/run/wireguard -e WG_LOG_LEVEL=debug leonnicolas/boringtun --foreground --disable-drop-privileges true "$1"
}

delete_interface() {
	docker rm --force "$1"
}

create_peer() {
	cat <<EOF | $KUBECTL_BINARY apply -f -
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
	$KUBECTL_BINARY delete peer "$1"
}

is_ready() {
	for pod in $($KUBECTL_BINARY -n "$1" get pods -o name -l "$2"); do
		if ! $KUBECTL_BINARY -n "$1" get "$pod" | tail -n 1 | grep -q Running; then
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
	$KIND_BINARY delete clusters $KIND_CLUSTER > /dev/null
	# Create the kind cluster.
	$KIND_BINARY create cluster --name $KIND_CLUSTER --config ./kind-config.yaml
	# Load the Kilo image into kind.
	docker tag "$KILO_IMAGE" squat/kilo:test
	$KIND_BINARY load docker-image squat/kilo:test --name $KIND_CLUSTER
	# Create the kubeconfig secret.
	$KUBECTL_BINARY create secret generic kubeconfig --from-file=kubeconfig="$KUBECONFIG" -n kube-system
	# Apply Kilo the the cluster.
	$KUBECTL_BINARY apply -f ../manifests/crds.yaml
	$KUBECTL_BINARY apply -f kilo-kind-userspace.yaml
	block_until_ready_by_name kube-system kilo-userspace 
	$KUBECTL_BINARY wait nodes --all --for=condition=Ready
	# Wait for CoreDNS.
	block_until_ready kube_system k8s-app=kube-dns
	# Ensure the curl helper is not scheduled on a control-plane node.
	$KUBECTL_BINARY apply -f helper-curl.yaml
	block_until_ready_by_name default curl
	$KUBECTL_BINARY taint node $KIND_CLUSTER-control-plane node-role.kubernetes.io/master:NoSchedule-
	$KUBECTL_BINARY apply -f https://raw.githubusercontent.com/heptoprint/adjacency/master/example.yaml
	block_until_ready_by_name adjacency adjacency
}

delete_cluster () {
	$KIND_BINARY delete clusters $KIND_CLUSTER
}

curl_pod() {
	$KUBECTL_BINARY get pods -l app.kubernetes.io/name=curl -o name | xargs -I{} "$KUBECTL_BINARY" exec {} -- /bin/sh -c "curl $*"
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

	for ip in $($KUBECTL_BINARY get pods -l app.kubernetes.io/name=adjacency -o jsonpath='{.items[*].status.podIP}'); do
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
	$KUBECTL_BINARY get pods -l app.kubernetes.io/name=curl -o name | xargs -I{} "$KUBECTL_BINARY" exec {} -- /bin/sh -c 'curl -m 1 -s adjacency:8080/?format=fancy'
	[ "$(curl_pod -m 1 -s adjacency:8080/?format=json | jq | grep -c true)" -eq "$1" ]
}

check_peer() {
	local INTERFACE=$1
	local PEER=$2
	local ALLOWED_IP=$3
	local GRANULARITY=$4
	create_interface "$INTERFACE"
	docker run --rm --entrypoint=/usr/bin/wg "$KILO_IMAGE" genkey > "$INTERFACE"
	assert "create_peer $PEER $ALLOWED_IP 10 $(docker run --rm --entrypoint=/bin/sh -v "$PWD/$INTERFACE":/key "$KILO_IMAGE" -c 'cat /key | wg pubkey')" "should be able to create Peer"
	assert "$KGCTL_BINARY showconf peer $PEER --mesh-granularity=$GRANULARITY > $PEER.ini" "should be able to get Peer configuration"
	assert "docker run --rm --network=host --cap-add=NET_ADMIN --entrypoint=/usr/bin/wg -v /var/run/wireguard:/var/run/wireguard -v $PWD/$PEER.ini:/peer.ini $KILO_IMAGE setconf $INTERFACE /peer.ini" "should be able to apply configuration from kgctl"
	docker run --rm --network=host --cap-add=NET_ADMIN --entrypoint=/usr/bin/wg -v /var/run/wireguard:/var/run/wireguard -v "$PWD/$INTERFACE":/key "$KILO_IMAGE" set "$INTERFACE" private-key /key
	docker run --rm --network=host --cap-add=NET_ADMIN --entrypoint=/sbin/ip "$KILO_IMAGE" address add "$ALLOWED_IP" dev "$INTERFACE"
	docker run --rm --network=host --cap-add=NET_ADMIN --entrypoint=/sbin/ip "$KILO_IMAGE" link set "$INTERFACE" up
	docker run --rm --network=host --cap-add=NET_ADMIN --entrypoint=/sbin/ip "$KILO_IMAGE" route add 10.42/16 dev "$INTERFACE"
	assert "retry 10 5 '' check_ping --local" "should be able to ping Pods from host"
	rm "$INTERFACE" "$PEER".ini
	delete_peer "$PEER"
	delete_interface "$INTERFACE"
}
