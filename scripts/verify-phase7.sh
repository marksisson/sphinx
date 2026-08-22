#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

for path in internal/audit internal/identity internal/policy internal/relic internal/secret internal/server internal/tomb internal/tombref launchd artifacts/sphinx-vs-setec.html; do
  if [ -e "$path" ]; then
    echo "superseded path remains: $path" >&2
    exit 1
  fi
done

retired='\b(relic|essence|facet|medjay|daemon|server|temple|riddle|petition|petitioner|explorer|envoy)\b|recovery (incantation|key)|\bprotect\b'
if rg -n -i "$retired" README.md docs/PRD.md docs/SCHEMAS.md docs/TERMINOLOGY.md decree.example.yaml schema.example.yaml sphinx.example.yaml global.example.yaml flake.nix; then
  echo 'retired vocabulary remains in current release documentation or metadata' >&2
  exit 1
fi
if rg -n -i -g '*.go' -g '!**/*_test.go' -g '!**/eff_large_wordlist.txt' "$retired" cmd internal; then
  echo 'retired implementation vocabulary remains in production Go code' >&2
  exit 1
fi
if rg -n -g '*.go' -g '!**/*_test.go' 'net/http|ListenAndServe|http\.Server|WhoIs\(' cmd internal; then
  echo 'network listener or remote-peer identity implementation remains' >&2
  exit 1
fi
if rg -n -g '*.go' -g '!**/*_test.go' 'internal/(audit|identity|policy|relic|secret|server|tomb)(["/])' .; then
  echo 'superseded package import remains' >&2
  exit 1
fi

systems="$(nix eval --json "path:$PWD#packages" --apply builtins.attrNames)"
[ "$systems" = '["aarch64-darwin"]' ]

nix develop -c go mod tidy
nix develop -c gofmt -w cmd internal
nix develop -c go test ./...
nix develop -c go test -race ./...
nix develop -c go test ./internal/chamber -run '^$' -fuzz '^FuzzParse$' -fuzztime=2s
nix develop -c go test ./internal/locator -run '^$' -fuzz '^FuzzParseRemote$' -fuzztime=2s
nix develop -c go vet ./...
nix flake check "path:$PWD"
git diff --check

echo 'Phase 7 superseded-code removal, documentation, examples, and aarch64-darwin release gates verified'
