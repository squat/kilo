#!/usr/bin/env bash
# shellcheck disable=SC1091
. lib.sh

setup_suite() {
	# shellcheck disable=SC2016
	block_until_ready_by_name kube-system kilo-userspace 
	_kubectl wait pod -l app.kubernetes.io/name=adjacency --for=condition=Ready --timeout 3m
}

test_graph_handler() {
    assert "curl_pod http://10.4.0.1:1107/graph?format=svg&layout=circo | grep -q '<svg'" "graph handler should produce SVG output"
    assert "curl_pod http://10.4.0.1:1107/graph?layout=circo | grep -q '<svg'" "graph handler should default to SVG output"
    assert "curl_pod http://10.4.0.1:1107/graph | grep -q '<svg'" "graph handler should default to SVG output"
    assert_fail "curl_pod http://10.4.0.1:1107/graph?layout=fake | grep -q '<svg'" "graph handler should reject invalid layout"
    assert_fail "curl_pod http://10.4.0.1:1107/graph?format=fake | grep -q '<svg'" "graph handler should reject invalid format"
}

test_health_handler() {
    assert "curl_pod http://10.4.0.1:1107/health" "health handler should return a status code of 200"
}

test_metrics_handler() {
    assert "curl_pod http://10.4.0.1:1107/metrics" "metrics handler should return a status code of 200"
    assert "(( $(curl_pod http://10.4.0.1:1107/metrics | egrep ^kilo_nodes | cut -d " " -f 2) > 0 ))" "metrics handler should provide metric: kilo_nodes > 0"
}
