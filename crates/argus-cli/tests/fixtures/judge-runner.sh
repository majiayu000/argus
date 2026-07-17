#!/bin/sh
set -eu

scenario_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$scenario_dir/judge-body.sh"
