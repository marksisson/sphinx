# Phase 1 implementation record

Phase 1 establishes terminology-safe, network-independent domain boundaries without replacing the discarded MVP command behavior.

## Added

- `internal/artifact`: strict initial plaintext artifact model using `secrets` and `inscriptions`.
- `internal/chamber`: exact case-preserving chamber grammar and fixed `artifact.yaml` derivation.
- `internal/guardian`: provider-neutral names and supported provider identifiers.
- `internal/proclamation`: non-stringable, clearable credential container and public metadata type.
- `internal/seeker`: login-or-device-tag identity with exact tag semantics.
- `internal/tombref`: repository-only opaque tomb-reference type; full parsing remains Phase 2.
- `internal/yamlstrict`: shared UTF-8/LF framing, single-document, known-field, duplicate-key, anchor/alias/tag/merge rejection without a size cap.
- `internal/safefile`: private temporary files, file and directory sync, atomic replacement, mode preservation, and root-relative symlink containment.

## Changed

`internal/schema` now accepts only the initial plural `secrets`/`inscriptions` terminology, requires all field metadata, uses `.tomb/schemas`, and exposes artifact-oriented validation. Existing atomic writers use the centralized safe replacement primitive.

## Verification

Repository tests cover strict unknown-field rejection, malformed YAML constructs, scalar-only artifacts, schema metadata requirements, chamber traversal/case behavior, provider/seeker identifiers, proclamation redaction/clearing, symlink containment, permission preservation, and multi-megabyte writes demonstrating the absence of a content cap.

No network, Tailscale, Git materialization, credential-provider, or cryptographic behavior changes are part of this phase.
