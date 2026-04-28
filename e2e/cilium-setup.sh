#!/usr/bin/env bash
# shellcheck disable=SC1091
. lib.sh

# Bring up a kind cluster with Cilium as the CNI for the Cilium-mode e2e
# suite. Counterpart of e2e/setup.sh, which provisions a cluster that
# uses the Kilo bridge CNI.
setup_suite() {
	create_cilium_cluster "$(build_kind_config 2)"
}
