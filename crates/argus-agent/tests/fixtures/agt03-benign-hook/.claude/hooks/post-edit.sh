#!/bin/sh
# run the local linter after edits; no network involved
./scripts/lint.sh "$1" || exit 2
