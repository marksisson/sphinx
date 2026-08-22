# Phase 8 implementation record

**Status: implementation and credential-free release gates complete; Apple credentials verified; official release awaits a reviewed clean commit.**

## Threat review

`docs/security/THREAT_MODEL_REVIEW.md` records the final review of local advisory-policy bypass, proclamation entropy and offline guessing, pinned dependency integrity, immutable Git locks and mutable worktrees, guardian/proclamation recipient changes, plaintext/private-material leakage, exact transaction recovery, and monotonic signed-state rollback resistance.

The review identifies no implementation contradiction with the accepted threat model. It preserves explicit residual risks: a guardian holder can decrypt outside Sphinx; stdout, process memory, trusted Git/tailscaled/Keychain, privileged local access, and deliberately replaced project configuration remain outside guarantees.

## Process hardening and leakage controls

`internal/hardening` sets and verifies both soft and hard macOS `RLIMIT_CORE` values as zero. The root command establishes this irreversible process control before any command body runs. Failure produces stable `security_control_failed` / exit 70 behavior and executes no command. Darwin unit tests inspect both limits; CLI tests inject a denial and verify empty stdout plus the JSON failure envelope.

Application initialization now captures `SPHINX_GUARDIAN` once and removes it before command parsing, reducing exposure through children and later common process-environment inspection. Provider tests verify removal. Immutable Go string/process-memory remnants remain documented rather than claimed erased.

Static and black-box gates verify that sensitive command/decryption packages contain no logging, plaintext temporary-file write, or subprocess boundary; secret/proclamation input has no argv flags; output remains stdout-only; completion contains no secret values; and errors do not reflect sensitive input. Journals continue to contain only encrypted/metadata exact images.

## Parser fuzzing

Dedicated fuzz targets now cover:

- exact chamber paths;
- remote tomb-reference grammar and canonical round trips;
- strict YAML framing and structure;
- plaintext artifact documents;
- encrypted SOPS metadata and recipient invariants;
- schemas; and
- decrees.

Seeds explicitly include anchors, aliases, custom tags, duplicate keys, merge keys, multiple documents, non-string keys, BOMs, and CRLF where applicable. Successful domain parses must encode/decode canonically. `scripts/verify-phase8.sh` runs each target independently so artifact and SOPS fuzzing cannot mask one another.

## Release hardening and publications

The repository now publishes:

- `docs/release/SUPPORT_MATRIX.md`
- `docs/release/RELEASE.md`
- `docs/operations/RECOVERY.md`
- `docs/operations/GUARDIAN_COMPROMISE.md`
- `docs/operations/PROCLAMATION_ROTATION.md`
- `docs/operations/ROLLBACK.md`

`scripts/verify-release-candidate.sh` builds an arm64 PIE with cgo, `-trimpath`, and stripped linker metadata; forces the system compiler/framework linkage; rejects Nix-store dynamic-library paths; applies and verifies an ad-hoc hardened-runtime signature; executes the binary through the core-control hook; emits a CycloneDX 1.5 SBOM from embedded Go build information; and verifies SHA-256 checksum generation.

`scripts/build-release-macos.sh` is the fail-closed official procedure. It requires a clean source tree, a Developer ID Application identity, and a notarytool Keychain profile. It runs all phase gates, builds the same system-linked binary, signs with hardened runtime and secure timestamp, verifies the signature, submits the archive, requires Apple's `Accepted` status, performs Gatekeeper assessment, and emits binary/archive/SBOM checksums plus signing, notarization, and Gatekeeper evidence.

The Nix development environment supplies Go but is deliberately stripped from release link flags: an earlier candidate correctly exposed an absolute Nix `libresolv` load path that hardened runtime rejected because Team IDs differed. Candidate and official scripts now use `/usr/bin/clang`, Apple system frameworks/libraries, and explicitly reject any `/nix/store` dynamic dependency.

## Verification

`scripts/verify-phase8.sh` runs static leakage/release checks, formatting and module tidiness, all tests, all-package race tests, all seven fuzz targets, vet, the hardened arm64 candidate build/sign/execute/SBOM/checksum gate, `nix flake check path:$PWD`, and diff hygiene.

The credential-free candidate gate passes on macOS Apple Silicon. The Nix development shell exposes a valid Developer ID Application identity and a usable notarytool Keychain profile without revealing credential values. The release procedure intentionally refuses the current uncommitted multi-phase working tree: Phase 8 remains open only until the reviewed source is committed cleanly, `scripts/build-release-macos.sh VERSION` succeeds, and its accepted release evidence is retained.
