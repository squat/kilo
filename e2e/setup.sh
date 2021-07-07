#!/usr/bin/env bash
# shellcheck disable=SC1091
. lib.sh

setup_suite() {
	create_cluster "$(build_kind_config 2)"
}
