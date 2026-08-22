#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

work=$(mktemp -d "${TMPDIR:-/tmp}/sphinx-phase0.XXXXXX")
trap 'rm -rf "$work"' EXIT

export GOBIN="$work/bin"
mkdir -p "$GOBIN"

go install filippo.io/age/cmd/age@v1.3.1
go install filippo.io/age/cmd/age-keygen@v1.3.1
go install github.com/getsops/sops/v3/cmd/sops@v3.12.1

[[ "$($GOBIN/age --version)" == "v1.3.1" ]]
"$GOBIN/sops" --version --check-for-updates=false | grep -q '^sops 3\.12\.1$'

go mod verify
SPHINX_TEST_AGE_BIN="$GOBIN/age" \
SPHINX_TEST_SOPS_BIN="$GOBIN/sops" \
  go test ./internal/phase0 -count=1 -v
