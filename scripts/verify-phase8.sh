#!/usr/bin/env bash
set -euo pipefail

for path in docs/security/THREAT_MODEL_REVIEW.md docs/release/SUPPORT_MATRIX.md docs/release/RELEASE.md docs/operations/RECOVERY.md docs/operations/GUARDIAN_COMPROMISE.md docs/operations/PROCLAMATION_ROTATION.md docs/operations/ROLLBACK.md; do
  test -s "$path"
done

rg -q 'RLIMIT_CORE' internal/hardening/core_darwin.go
rg -q 'security_control_failed' cmd/sphinx/app.go
if rg -n --glob '*.go' --glob '!**/*_test.go' '(log\.Print|slog\.|os\.CreateTemp|os\.WriteFile|exec\.Command)' cmd/sphinx internal/artifact internal/proclamation internal/reveal; then
  echo 'sensitive command/decryption boundary contains logging, plaintext file, or subprocess operation' >&2
  exit 1
fi
if rg -n --glob '*.go' --glob '!**/*_test.go' 'String(Var|SliceVar).*"(passphrase|proclamation-text|secret-value|value-file)"' cmd/sphinx; then
  echo 'private-value command-line input remains' >&2
  exit 1
fi

nix develop -c gofmt -w cmd internal scripts/generate-sbom.go
nix develop -c go mod tidy
nix develop -c go test ./...
nix develop -c go test -race ./...
for target in \
  './internal/chamber FuzzParse' \
  './internal/locator FuzzParseRemote' \
  './internal/yamlstrict FuzzValidateSyntax' \
  './internal/artifact FuzzDecode' \
  './internal/artifact FuzzSOPSMetadata' \
  './internal/schema FuzzDecode' \
  './internal/decree FuzzDecode'; do
  read -r package fuzz <<<"$target"
  nix develop -c go test "$package" -run='^$' -fuzz="^${fuzz}$" -fuzztime=2s
done
nix develop -c go vet ./...
nix develop -c ./scripts/verify-release-candidate.sh
nix flake check "path:$PWD"
git diff --check

echo 'Phase 8 threat review, parser fuzzing, leakage controls, and hardened release-candidate gates verified'
