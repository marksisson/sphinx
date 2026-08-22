# macOS Apple Silicon release procedure

Only a release operator with an Apple Developer ID Application certificate and notarization credentials can publish a Sphinx release.

## One-time notarization profile

Store credentials with Apple's tool; do not pass passwords or API private keys on the Sphinx command line:

```sh
xcrun notarytool store-credentials sphinx-notary \
  --apple-id OPERATOR_APPLE_ID \
  --team-id APPLE_TEAM_ID
```

The tool prompts securely for the app-specific password and stores the profile in Keychain. App Store Connect API-key profiles are also supported by `notarytool` and are preferred for automation.

## Build and submit

Start from a reviewed clean commit on macOS Apple Silicon:

```sh
nix develop
export SPHINX_CODESIGN_IDENTITY='Developer ID Application: Example (TEAMID)'
export SPHINX_NOTARY_PROFILE='sphinx-notary'
scripts/build-release-macos.sh v0.1.0
```

The procedure requires a clean source tree, records the exact verified `HEAD` in `RELEASE.txt`, runs every phase gate, builds an arm64 PIE with cgo and the system Apple frameworks, rejects Nix-store dynamic-library paths, applies a hardened-runtime signature and secure timestamp, verifies the signature, executes the binary's core-limit path, submits the archive to Apple, requires `Accepted`, runs Gatekeeper assessment, generates a CycloneDX 1.5 SBOM from embedded Go build information, and writes SHA-256 checksums.

`dist/VERSION/` contains:

- `sphinx`
- `sphinx-VERSION-darwin-arm64.zip`
- `sphinx-VERSION.sbom.cdx.json`
- `SHA256SUMS`
- `codesign.txt`
- `notarization.txt`
- `gatekeeper.txt`
- `RELEASE.txt`

Publish the archive, SBOM, checksums, and evidence files together. Verify the uploaded downloads against `SHA256SUMS` from a separate machine before announcing the release. Keep the recorded source commit, exact `flake.lock`, `go.sum`, and CI log with the release record. The Go build disables automatic VCS stamping because this repository may be checked out as a linked Git worktree, whose common administrative directory is misidentified by the Go tool; the fail-closed clean-tree check and explicit `source_commit` provide the release provenance instead.

## Credential-free candidate check

`scripts/verify-release-candidate.sh` builds the same system-linked arm64 PIE, applies an ad-hoc hardened-runtime signature, executes it, and verifies SBOM/checksum generation. It proves local packaging mechanics only. Ad-hoc signing is not a Developer ID signature, is not notarizable, and must never be distributed as an official release.
