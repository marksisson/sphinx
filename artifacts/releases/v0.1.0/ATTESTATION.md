# Sphinx v0.1.0 release evidence

- Source commit: `6f60cbb6391025c5aec8bf262d2dcf85b1a5d6bf`
- Platform: `darwin/arm64`
- Distribution: `sphinx-v0.1.0-darwin-arm64.dmg`
- Binary: arm64 PIE, cgo enabled, system Apple frameworks, no Nix-store dynamic-library paths
- Signature: Developer ID Application, Team ID `3ZFD84NJ64`, hardened runtime, secure timestamp
- Apple notarization submission: `8d1637b5-2382-401f-8a5d-430fd936855e`
- Apple notarization result: `Accepted`
- Ticket: stapled and validated on the disk image
- Gatekeeper: `accepted`, source `Notarized Developer ID`
- SBOM: CycloneDX 1.5, 131 linked Go module components

`SHA256SUMS` binds the signed binary, stapled disk image, and published SBOM. The disk image itself is emitted under ignored local `dist/v0.1.0/` for attachment to the release distribution channel; it is not stored in Git.
