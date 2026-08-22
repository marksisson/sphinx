#!/usr/bin/env bash
set -euo pipefail
[[ $(uname -s) == Darwin && $(uname -m) == arm64 ]] || { echo 'candidate verification requires macOS Apple Silicon' >&2; exit 69; }
for tool in go codesign file otool; do command -v "$tool" >/dev/null || { echo "missing candidate tool: $tool" >&2; exit 69; }; done
[[ $(go env GOVERSION) == 'go1.26.5' ]] || { echo 'candidate verification requires Go 1.26.5' >&2; exit 69; }

tmp=$(mktemp -d "${TMPDIR:-/tmp}/sphinx-release.XXXXXXXX")
trap 'rm -rf "$tmp"' EXIT
env -u NIX_LDFLAGS -u NIX_CFLAGS_COMPILE -u NIX_CC -u NIX_BINTOOLS -u DEVELOPER_DIR -u SDKROOT \
  CC=/usr/bin/clang CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 \
  go build -buildvcs=false -trimpath -buildmode=pie -ldflags='-s -w' -o "$tmp/sphinx" ./cmd/sphinx
if otool -L "$tmp/sphinx" | grep -q /nix/store; then
  echo 'release candidate contains a Nix-store dynamic-library path' >&2
  exit 1
fi
file "$tmp/sphinx" | grep -Eq 'Mach-O 64-bit (executable arm64|arm64 executable)'
otool -hv "$tmp/sphinx" | grep -q PIE
codesign --force --options runtime --sign - "$tmp/sphinx"
codesign --verify --deep --strict --verbose=2 "$tmp/sphinx"
/usr/bin/env -i HOME="$HOME" PATH= "$tmp/sphinx" completion bash >/dev/null
go run ./scripts/generate-sbom.go "$tmp/sphinx" v0.0.0-candidate "$tmp/sbom.cdx.json"
test -s "$tmp/sbom.cdx.json"
grep -Fq '"name": "github.com/go-git/go-git/v6"' "$tmp/sbom.cdx.json"
grep -Fq '"version": "v6.0.0-alpha.5.0.20260821142625-374c354884f1"' "$tmp/sbom.cdx.json"
grep -Fq '"name": "github.com/cloudflare/circl"' "$tmp/sbom.cdx.json"
grep -Fq '"version": "v1.6.3"' "$tmp/sbom.cdx.json"
shasum -a 256 "$tmp/sphinx" "$tmp/sbom.cdx.json" >"$tmp/SHA256SUMS"
test "$(wc -l <"$tmp/SHA256SUMS" | tr -d ' ')" = 2
echo 'Hardened arm64 PIE candidate, ad-hoc signature, empty-PATH startup, runtime core control, SBOM, and checksums verified'
