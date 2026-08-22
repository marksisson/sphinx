# Sphinx initial-release product requirements

## Product

Sphinx is a synchronous local CLI for schema-conforming encrypted artifacts stored in Git tombs. It provides interactive administrative authoring and live identity-aware reveal without owning Git history or transport.

The supported release platform is macOS Apple Silicon (`darwin/arm64`).

## Security boundary

Sphinx provides a conforming-use authorization boundary, not DRM. Every reveal must:

1. resolve an enrolled tomb to its exact locked commit;
2. verify the externally pinned proclamation fingerprint and contiguous cross-signed transitions;
3. verify the detached hybrid decree signature before parsing policy;
4. verify exhaustive exact-byte artifact and schema locks;
5. request one fresh local tailscaled status and require a running, online self node with a login and/or device tag;
6. authorize the requested exact chamber through a signed allow rule;
7. load configured guardians in deterministic project order and use the first recipient intersection that unwraps the data key;
8. verify the SOPS MAC and tomb-local schema; and
9. write requested plaintext only to stdout.

There is no offline mode, identity cache, environment identity override, grace period, remote-peer lookup, local event database, or persistent plaintext.

A seeker is identified independently by exact Tailscale login or exact `tag:` device tag. A guardian holder can use compatible cryptographic tooling outside Sphinx, so decree enforcement cannot prevent direct use of guardian identity material.

## Repository model

A tomb is a Git repository. `.tomb/` is its only metadata root:

```text
.tomb/tomb.yaml
.tomb/decree.yaml
.tomb/decree.yaml.sig
.tomb/rotations/.keep
.tomb/rotations/NNNNNNNN.yaml
.tomb/rotations/NNNNNNNN.from.sig
.tomb/rotations/NNNNNNNN.to.sig
.tomb/schemas/NAME/vN.yaml
CHAMBER/artifact.yaml
```

A chamber is an exact case-sensitive printable-ASCII path. It cannot be absolute, traverse, contain empty components, or reserve `.git`. Case-colliding chambers remain distinct.

Managed tomb files must be regular Git blobs with no symbolic links, submodules, LFS, filters, working-tree encoding, or line-ending transformations. Immutable reads come from a bare object cache and exact Git objects, never a checkout.

Sphinx mutates only explicit `path:` references to existing caller-managed non-bare worktrees. It never initializes Git, changes the index, stages, commits, signs Git objects, creates branches, merges, pushes, stashes, or performs broad reset operations.

## Tomb references and project locks

Accepted repository reference forms are `github:`, `git+https://`, `git+ssh://`, and explicit `path:`. At most one `?ref=` or `?rev=` selector is accepted. Repository subdirectory and file selectors do not exist. Embedded credentials and unsafe path resolution are rejected.

The optional XDG global configuration contains manually maintained aliases only and is read-only to all commands. The project file is `<git-root>/.sphinx/config.yaml`. A project lock contains the canonical reference, exact 40-hex commit, proclamation fingerprint, positive decree generation, UTC lock timestamp, and ordered guardian selections. Omitted `--tomb` means the alias exactly `default`.

Enrollment derives trust data only from a fully verified current tomb, displays the fingerprint through the controlling terminal, and requires explicit approval. Updates resolve each mutable reference once, require the candidate commit to descend from the lock, validate the complete trust/content state, reject generation rollback and same-generation substitution, then atomically install all accepted lock changes.

## Cryptography

Artifacts use SOPS v3.12.1 semantics in-process. AES-256-GCM encrypts only the top-level `secrets` mapping; `inscriptions` remain readable and are unauthenticated until MAC verification.

Every artifact contains exactly one proclamation recipient followed by zero or more unique guardian recipients. All recipients use native `mlkem768x25519-v1`. Classical age recipients, extension recipients, KMS, PGP, SSH, threshold groups, Shamir configuration, duplicate recipients, and multiple proclamation recipients are rejected.

Proclamations are generated as ten unbiased words from the embedded EFF large word list. Fixed `argon2id-v1` parameters are 256 MiB, three iterations, four lanes, and 32-byte salt/output. Independent HKDF-SHA-256 labels derive native age and hybrid signature seeds. Decree and transition signatures require both Ed25519 and ML-DSA-65 components under `ed25519+mldsa65-v1`.

Every inscription update, full or selected-secret reseal, guardian recipient change, and proclamation rotation creates a fresh independent 32-byte artifact data key and fully re-encrypts the artifact. Artifact creation is proclamation-only. An artifact with no guardian remains administratively decryptable but cannot be revealed by a seeker.

## Formats

All Sphinx YAML is strict UTF-8 without BOM, LF-only, and ends with exactly one LF. Parsers reject unknown fields, duplicate keys, anchors, aliases, custom tags, merge keys, non-string mapping keys, and multiple documents.

Artifacts contain only named, non-null top-level string, integer, or boolean scalars beneath inherent plural `secrets` and `inscriptions` mappings. Schemas support `string`, `integer`, `boolean`, and string-valued `enum` fields. Required strings cannot be empty. Nested values, sequences, defaults, and coercion are not supported.

Schema references are immutable per artifact and have exact form `name/vN`, resolving only to `.tomb/schemas/name/vN.yaml` at the same commit.

The version-1 decree is readable, allow-only, default-deny, and hybrid-signed. It contains a positive generation, exhaustive sorted unique SHA-256 locks, and rules containing only `name`, `seekers`, and `artifacts`. Chamber patterns are anchored and case-sensitive; `*` matches within one path segment and an exact `**` segment matches zero or more segments.

The version-1 manifest fixes tomb ID, KDF, age suite, signature suite, proclamation recipient/public keys, salt, and fingerprint. Proclamation rotation appends a fixed-width contiguous transition signed separately by old and new proclamation identities.

Sphinx defines no maximum artifact, schema, decree, individual-secret, or repository size.

## Credential providers

Guardians are provider-authoritative records and private identities are never stored in a filesystem registry.

- `apple-icloud-keychain` is the macOS default.
- `apple-login-keychain` is selected explicitly.
- `environment` reads only `SPHINX_GUARDIAN`, is read-only, and supports at most one selection per project configuration.

Guardian show/list output includes non-secret metadata only and does not export identity or recipient values. There is no guardian sharing, import, or export workflow.

## CLI requirements

The initial command matrix is [COMMANDS.md](COMMANDS.md). Artifact authoring is interactive only and requires a controlling terminal. No secret or proclamation input is accepted from argv, stdin, files, or general environment variables.

Decrypted values are emitted only on stdout. All-secret human output is a secrets-only YAML document in schema order. A selected value is one canonical scalar with no added newline. Terminal stdout requires a conspicuous warning and confirmation before plaintext. Clipboard, plaintext file, temporary file, dedicated descriptor, and child-command modes do not exist.

Before any command body executes, Sphinx must set and verify both macOS soft and hard core-file size limits as zero and fail closed if that control cannot be established. Application initialization captures `SPHINX_GUARDIAN` once and removes it before command parsing; private material is still considered resident in process memory until exit. No handled error, diagnostic, warning, completion, or subprocess receives secret values.

`--json` emits one deterministic newline-terminated version-1 success object on stdout or one error object on stderr. Errors contain stable identifiers and no secret values. Handled failures use the documented BSD `sysexits` subset; no handled path intentionally exits 1. Completion is the sole non-envelope command.

Inspection performs no identity lookup or decryption, exposes only readable public fields, sets `verified: false`, and always emits `unverified_inscriptions`. Artifact validation follows the authenticated reveal path but emits no secrets.

## Transactions and recovery

Every authorized signed-state mutation increments decree generation exactly once and regenerates exhaustive locks and detached signature. Multi-artifact guardian changes and proclamation rotation are single transactions.

Transactions use an interprocess lock and exact path-scoped journal below the Git administrative directory. Preparation records exact pre/post bytes, existence, modes, and SHA-256 digests. Signed dependencies are read-only guards, not journal targets. Installation uses atomic replacement and directory synchronization, validates the complete virtual and installed state, and preserves existing non-executable modes. New executable files and special mode bits are rejected.

A crash blocks further mutations. Proclamation-authorized rollback restores only listed paths whose state still equals a recorded image, refuses third-party edits, and never modifies unrelated files or Git state. Corrupt-journal diagnostics retain a separately synchronized exact target list.

## Non-goals

The initial release does not include:

- network listeners or remote protocols;
- background lifecycle management;
- local audit persistence;
- Git history or transport management;
- automatic global alias mutation;
- offline reveal;
- guardian portability workflows;
- recipient thresholds;
- suite rotation;
- migration readers or compatibility formats;
- plaintext destinations other than stdout; or
- platforms other than macOS Apple Silicon.

## Acceptance

The release must pass all package tests, race tests, parser fuzz smoke tests, static analysis, phase verification scripts, and `nix flake check` on `aarch64-darwin`. Black-box CLI tests must cover exact commands and flags, JSON envelopes and exit codes, fail-closed core-dump control, controlling-terminal failures, fresh tailscaled status, signed policy authorization, provider selection, MAC/schema validation, terminal confirmation, stdout-only plaintext, crash recovery, and absence of Git history/index side effects.

The distributed binary must be an arm64 PIE built with cgo and no Nix-store dynamic-library paths, signed with a Developer ID Application certificate and hardened runtime plus secure timestamp, contained in a notarized and stapled disk image accepted by Gatekeeper, and accompanied by binary/disk-image/SBOM SHA-256 checksums, a CycloneDX SBOM generated from embedded Go build information, the support/interoperability matrix, threat-model review, and recovery/compromise/rotation/rollback procedures.
