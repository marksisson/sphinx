#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

go test ./internal/artifact ./internal/artifactmutation ./internal/transaction ./internal/schema

work=$(mktemp -d "${TMPDIR:-/tmp}/sphinx-phase4.XXXXXX")
trap 'rm -rf "$work"' EXIT
export GOBIN="$work/bin"
mkdir -p "$GOBIN"
go install github.com/getsops/sops/v3/cmd/sops@v3.12.1
"$GOBIN/sops" --version --check-for-updates=false | grep -q '^sops 3\.12\.1$'

proclamation=$(awk -F= '/^proclamation=/{print substr($0,index($0,"=")+1)}' testdata/phase4/test-identities.txt)
guardian=$(awk -F= '/^guardian=/{print substr($0,index($0,"=")+1)}' testdata/phase4/test-identities.txt)
temporary="$work/plaintext"
mkdir -p "$temporary"

SOPS_AGE_KEY="$proclamation" "$GOBIN/sops" --decrypt testdata/phase4/proclamation-only.sops.yaml >"$temporary/proclamation.yaml"
SOPS_AGE_KEY="$guardian" "$GOBIN/sops" --decrypt testdata/phase4/multi-guardian.sops.yaml >"$temporary/guardian.yaml"
for plaintext in "$temporary/proclamation.yaml" "$temporary/guardian.yaml"; do
  ! grep -F 'ENC[AES256_GCM' "$plaintext" >/dev/null
  grep -F 'api_key: fixture-secret' "$plaintext" >/dev/null
  grep -F 'replicas: 3' "$plaintext" >/dev/null
  grep -F 'enabled: true' "$plaintext" >/dev/null
  grep -F 'environment: production' "$plaintext" >/dev/null
done

echo "Phase 4 native SOPS interoperability verified"
