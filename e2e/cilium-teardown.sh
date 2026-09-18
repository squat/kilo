#!/usr/bin/env bash
# shellcheck disable=SC1091
. lib.sh

teardown_suite () {
	if [ -n "$E2E_SKIP_TEARDOWN_ON_FAILURE" ]; then
		return
	fi
	delete_cluster
}
