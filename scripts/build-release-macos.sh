#!/usr/bin/env bash
set -euo pipefail

version=${1:-}
case "$version" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) echo 'usage: scripts/build-release-macos.sh vMAJOR.MINOR.PATCH' >&2; exit 64 ;;
esac

[[ $(uname -s) == Darwin && $(uname -m) == arm64 ]] || { echo 'release requires macOS Apple Silicon' >&2; exit 69; }
: "${SPHINX_CODESIGN_IDENTITY:?set SPHINX_CODESIGN_IDENTITY to a Developer ID Application identity}"
: "${SPHINX_NOTARY_PROFILE:?set SPHINX_NOTARY_PROFILE to an xcrun notarytool Keychain profile}"
for tool in go git codesign xcrun ditto file otool shasum spctl; do command -v "$tool" >/dev/null || { echo "missing release tool: $tool" >&2; exit 69; }; done

if [[ -n $(git status --porcelain) ]]; then
  echo 'release source tree must be clean' >&2
  exit 75
fi

root=$(git rev-parse --show-toplevel)
cd "$root"
source_commit=$(git rev-parse --verify HEAD)
for gate in scripts/verify-phase0.sh scripts/verify-phase4.sh scripts/verify-phase5.sh scripts/verify-phase6.sh scripts/verify-phase7.sh scripts/verify-phase8.sh; do "$gate"; done

out="$root/dist/$version"
rm -rf "$out"
mkdir -p "$out"
env -u NIX_LDFLAGS -u NIX_CFLAGS_COMPILE -u NIX_CC -u NIX_BINTOOLS -u DEVELOPER_DIR -u SDKROOT \
  CC=/usr/bin/clang CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 \
  go build -buildvcs=false -trimpath -buildmode=pie -ldflags='-s -w' -o "$out/sphinx" ./cmd/sphinx
if otool -L "$out/sphinx" | grep -q /nix/store; then
  echo 'release binary contains a Nix-store dynamic-library path' >&2
  exit 1
fi
file "$out/sphinx" | grep -Eq 'Mach-O 64-bit (executable arm64|arm64 executable)'
otool -hv "$out/sphinx" | grep -q PIE

codesign --force --options runtime --timestamp --sign "$SPHINX_CODESIGN_IDENTITY" "$out/sphinx"
codesign --verify --deep --strict --verbose=2 "$out/sphinx"
codesign -d --verbose=4 "$out/sphinx" 2>"$out/codesign.txt"

"$out/sphinx" completion bash >/dev/null
ditto -c -k --keepParent "$out/sphinx" "$out/sphinx-$version-darwin-arm64.zip"
xcrun notarytool submit "$out/sphinx-$version-darwin-arm64.zip" --keychain-profile "$SPHINX_NOTARY_PROFILE" --wait | tee "$out/notarization.txt"
grep -q 'status: Accepted' "$out/notarization.txt"
spctl --assess --type execute --verbose=2 "$out/sphinx" 2>"$out/gatekeeper.txt"

go run ./scripts/generate-sbom.go "$out/sphinx" "$version" "$out/sphinx-$version.sbom.cdx.json"
(
  cd "$out"
  shasum -a 256 sphinx "sphinx-$version-darwin-arm64.zip" "sphinx-$version.sbom.cdx.json" > SHA256SUMS
)

cat >"$out/RELEASE.txt" <<EOF
Sphinx $version
source_commit: $source_commit
platform: darwin/arm64
artifact: sphinx-$version-darwin-arm64.zip
signature: Developer ID hardened runtime
notarization: Accepted
support matrix: docs/release/SUPPORT_MATRIX.md
SBOM: sphinx-$version.sbom.cdx.json
checksums: SHA256SUMS
EOF
printf 'Release artifacts: %s\n' "$out"
