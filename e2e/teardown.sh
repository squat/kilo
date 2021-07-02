#!/usr/bin/env bash
# shellcheck disable=SC1091
. lib.sh

teardown_suite () {
	delete_cluster
}
