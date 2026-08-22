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
for tool in go git codesign xcrun hdiutil file otool shasum spctl; do command -v "$tool" >/dev/null || { echo "missing release tool: $tool" >&2; exit 69; }; done

if [[ -n $(git status --porcelain) ]]; then
  echo 'release source tree must be clean' >&2
  exit 75
fi

root=$(git rev-parse --show-toplevel)
cd "$root"
source_commit=$(git rev-parse --verify HEAD)
scripts/verify.sh

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
stage=$(mktemp -d "$out/.dmg-stage.XXXXXXXX")
trap 'rm -rf "$stage"' EXIT
cp "$out/sphinx" "$stage/sphinx"
hdiutil create -quiet -volname Sphinx -srcfolder "$stage" -ov -format UDZO "$out/sphinx-$version-darwin-arm64.dmg"
codesign --force --timestamp --sign "$SPHINX_CODESIGN_IDENTITY" "$out/sphinx-$version-darwin-arm64.dmg"
xcrun notarytool submit "$out/sphinx-$version-darwin-arm64.dmg" --keychain-profile "$SPHINX_NOTARY_PROFILE" --wait | tee "$out/notarization.txt"
grep -q 'status: Accepted' "$out/notarization.txt"
xcrun stapler staple "$out/sphinx-$version-darwin-arm64.dmg"
xcrun stapler validate "$out/sphinx-$version-darwin-arm64.dmg"
codesign --verify --strict --verbose=2 "$out/sphinx-$version-darwin-arm64.dmg"
spctl --assess --type open --context context:primary-signature --verbose=2 "$out/sphinx-$version-darwin-arm64.dmg" 2>"$out/gatekeeper.txt"

go run ./scripts/generate-sbom.go "$out/sphinx" "$version" "$out/sphinx-$version.sbom.cdx.json"
(
  cd "$out"
  shasum -a 256 sphinx "sphinx-$version-darwin-arm64.dmg" "sphinx-$version.sbom.cdx.json" > SHA256SUMS
)

cat >"$out/RELEASE.txt" <<EOF
Sphinx $version
source_commit: $source_commit
platform: darwin/arm64
artifact: sphinx-$version-darwin-arm64.dmg
signature: Developer ID hardened runtime
notarization: Accepted
support matrix: docs/release/SUPPORT_MATRIX.md
SBOM: sphinx-$version.sbom.cdx.json
checksums: SHA256SUMS
EOF
printf 'Release artifacts: %s\n' "$out"
