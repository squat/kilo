#!/usr/bin/env bash
# shellcheck disable=SC1091
. lib.sh

setup_suite() {
	# shellcheck disable=SC2016
	_kubectl patch ds -n kube-system kilo -p '{"spec": {"template":{"spec":{"containers":[{"name":"kilo","args":["--hostname=$(NODE_NAME)","--create-interface=false","--kubeconfig=/etc/kubernetes/kubeconfig","--mesh-granularity=full"]}]}}}}'
	block_until_ready_by_name kube-system kilo-userspace 
	_kubectl wait pod -l app.kubernetes.io/name=adjacency --for=condition=Ready --timeout 3m
}

test_graph_handler() {
    assert "curl_pod http://10.4.0.1:1107/graph?format=svg&layout=circo | grep -q '<svg'"
    assert "curl_pod http://10.4.0.1:1107/graph&layout=circo | grep -q '<svg'"
    assert "curl_pod http://10.4.0.1:1107/graph | grep -q '<svg'"
    assert _not "curl_pod http://10.4.0.1:1107/graph?format=svg&layout=fake | grep -q '<svg'"
}

test_health_handler() {
    assert "curl_pod http://10.4.0.1:1107/health"
}

test_metrics_handler() {
    assert "curl_pod http://10.4.0.1:1107/metrics"
}
