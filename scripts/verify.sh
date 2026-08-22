#!/usr/bin/env bash
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

work=$(mktemp -d "${TMPDIR:-/tmp}/sphinx-verify.XXXXXXXX")
trap 'rm -rf "$work"' EXIT
export GOBIN="$work/bin"
mkdir -p "$GOBIN"

for path in internal/audit internal/identity internal/policy internal/relic internal/secret internal/server internal/tombref launchd artifacts/sphinx-vs-setec.html; do
  if [[ -e "$path" ]]; then
    echo "unsupported path exists: $path" >&2
    exit 1
  fi
done

retired='\b(relic|essence|facet|medjay|daemon|server|temple|riddle|petition|petitioner|explorer|envoy)\b|recovery (incantation|key)|\bprotect\b'
if rg -n -i "$retired" README.md docs/PRD.md docs/SCHEMAS.md docs/TERMINOLOGY.md docs/COMMANDS.md docs/security docs/release docs/operations docs/examples flake.nix; then
  echo 'retired vocabulary remains in current release documentation or metadata' >&2
  exit 1
fi
if rg -n -i -g '*.go' -g '!**/*_test.go' -g '!**/eff_large_wordlist.txt' "$retired" cmd internal; then
  echo 'retired implementation vocabulary remains in production Go code' >&2
  exit 1
fi
if rg -n -g '*.go' -g '!**/*_test.go' -g '!internal/git/transport/**' 'net/http|ListenAndServe|http\.Server|http\.Client|WhoIs\(' cmd internal; then
  echo 'network listener, unauthorized HTTP client, or remote-peer identity implementation remains' >&2
  exit 1
fi
if rg -n -g '*.go' -g '!**/*_test.go' 'ListenAndServe|http\.Server|net\.Listen\(' internal/git/transport; then
  echo 'Git transport package contains a listener or server' >&2
  exit 1
fi
if rg -n -g '*.go' -g '!**/*_test.go' '"os/exec"|exec\.Command' cmd internal; then
  echo 'production Go code contains an external-process execution path' >&2
  exit 1
fi
if [[ -e internal/git/env ]]; then
  echo 'transitional Git subprocess environment package remains' >&2
  exit 1
fi
if rg -n -g '*.go' -g '!**/*_test.go' -g '!internal/testgit/**' 'internal/testgit' cmd internal; then
  echo 'production Go code imports the native-Git test oracle' >&2
  exit 1
fi
if rg -n -g '*.go' -g '!**/*_test.go' -g '!internal/git/**' 'github.com/go-git/' cmd internal; then
  echo 'production package outside internal/git imports go-git' >&2
  exit 1
fi
if rg -n -g '*.go' -g '!**/*_test.go' 'internal/(audit|identity|policy|relic|secret|server)(["/])' .; then
  echo 'unsupported package import exists' >&2
  exit 1
fi
if rg -n -g '*.go' -g '!**/*_test.go' 'exec\.Command|WhoIs\(' internal/decree internal/tomb/state internal/seeker internal/reveal internal/proclamation/rotation; then
  echo 'authorization boundary invokes an external command or remote-peer WhoIs' >&2
  exit 1
fi

for path in docs/security/THREAT_MODEL.md docs/release/SUPPORT_MATRIX.md docs/release/PROCESS.md docs/operations/RECOVERY.md docs/operations/GUARDIAN_COMPROMISE.md docs/operations/PROCLAMATION_ROTATION.md docs/operations/ROLLBACK.md; do
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

systems=$(nix eval --json "path:$PWD#packages" --apply builtins.attrNames)
[[ "$systems" == '["aarch64-darwin"]' ]]
[[ $(nix develop -c go env GOVERSION) == 'go1.26.5' ]]
[[ $(nix develop -c git --version) == 'git version 2.55.0' ]]

nix develop -c gofmt -w cmd internal scripts/generate-sbom.go
nix develop -c go mod tidy
nix develop -c go mod verify
nix develop -c go install filippo.io/age/cmd/age@v1.3.1
nix develop -c go install filippo.io/age/cmd/age-keygen@v1.3.1
nix develop -c go install github.com/getsops/sops/v3/cmd/sops@v3.12.1
[[ "$("$GOBIN/age" --version)" == 'v1.3.1' ]]
"$GOBIN/sops" --version --check-for-updates=false | grep -q '^sops 3\.12\.1$'

nix develop -c env \
  SPHINX_TEST_AGE_BIN="$GOBIN/age" \
  SPHINX_TEST_SOPS_BIN="$GOBIN/sops" \
  go test ./internal/interoperability -count=1 -v

proclamation=$(awk -F= '/^proclamation=/{print substr($0,index($0,"=")+1)}' testdata/sops/test-identities.txt)
guardian=$(awk -F= '/^guardian=/{print substr($0,index($0,"=")+1)}' testdata/sops/test-identities.txt)
mkdir -p "$work/plaintext"
SOPS_AGE_KEY="$proclamation" "$GOBIN/sops" --decrypt testdata/sops/proclamation-only.sops.yaml >"$work/plaintext/proclamation.yaml"
SOPS_AGE_KEY="$guardian" "$GOBIN/sops" --decrypt testdata/sops/multi-guardian.sops.yaml >"$work/plaintext/guardian.yaml"
for plaintext in "$work/plaintext/proclamation.yaml" "$work/plaintext/guardian.yaml"; do
  ! grep -F 'ENC[AES256_GCM' "$plaintext" >/dev/null
  grep -F 'api_key: fixture-secret' "$plaintext" >/dev/null
  grep -F 'replicas: 3' "$plaintext" >/dev/null
  grep -F 'enabled: true' "$plaintext" >/dev/null
  grep -F 'environment: production' "$plaintext" >/dev/null
done

nix develop -c go test ./...
nix develop -c go test -race ./...

bin="$work/sphinx"
nix develop -c go build -buildvcs=false -o "$bin" ./cmd/sphinx
set +e
stdout=$("$bin" --json artifact reveal --listen-address 127.0.0.1:8080 production/api 2>"$work/cli-error.json")
status=$?
set -e
[[ "$status" -eq 64 ]]
[[ -z "$stdout" ]]
python3 - "$work/cli-error.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1]))
assert value == {"version": 1, "ok": False, "error": {"code": "usage", "message": "unknown flag: --listen-address", "retryable": False}}
PY
help=$("$bin" --help)
for command in tomb artifact guardian decree proclamation; do grep -q "  $command" <<<"$help"; done
if grep -Eiq '\b(listen|online)\b' <<<"$help"; then
  echo 'network command surface remains in root help' >&2
  exit 1
fi
if rg -n -g '*.go' -g '!**/*_test.go' -- '--(listen-address|recovery|stdin|from-json|clipboard|output|file|fd|exec)\b' cmd/sphinx; then
  echo 'forbidden CLI input/output mode remains' >&2
  exit 1
fi

for target in \
  './internal/chamber FuzzParse' \
  './internal/locator FuzzParseRemote' \
  './internal/yaml/strict FuzzValidateSyntax' \
  './internal/artifact FuzzDecode' \
  './internal/artifact FuzzSOPSMetadata' \
  './internal/schema FuzzDecode' \
  './internal/decree FuzzDecode'; do
  read -r package fuzz <<<"$target"
  nix develop -c go test "$package" -run='^$' -fuzz="^${fuzz}$" -fuzztime=1000x
done

nix develop -c go vet ./...
nix develop -c ./scripts/verify-release-candidate.sh
nix flake check "path:$PWD"
runtime_package=$(nix build "path:$PWD" --no-link --print-out-paths)
if nix-store -q --references "$runtime_package" | grep -Eq '/[^/]*git([.-]|$)'; then
  echo 'runtime Nix package retains a Git executable reference' >&2
  exit 1
fi
git diff --check

echo 'Sphinx tests, races, fuzzing, interoperability, security, CLI, and release-candidate gates verified'
