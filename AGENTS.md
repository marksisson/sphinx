# Repository guide for coding agents

This file applies to the entire repository. Sphinx is a security-sensitive macOS Apple Silicon CLI. Preserve the current architecture and trust boundaries unless a change intentionally updates the governing ADRs, specifications, tests, and this guide.

## Start here

Read these before changing behavior:

1. [`README.md`](README.md) — supported product and user workflow.
2. [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — normative architecture, formats, and trust boundaries.
3. [`docs/COMMANDS.md`](docs/COMMANDS.md) — current command matrix.
4. [`docs/PRD.md`](docs/PRD.md) — release requirements and non-goals.
5. [`docs/TERMINOLOGY.md`](docs/TERMINOLOGY.md) — canonical vocabulary.
6. [`docs/adr/README.md`](docs/adr/README.md) — accepted design decisions.
7. [`docs/security/THREAT_MODEL.md`](docs/security/THREAT_MODEL.md) — guarantees and residual risks.

For format work, also read [`docs/SCHEMAS.md`](docs/SCHEMAS.md) and [`docs/examples/`](docs/examples/). For release work, read [`docs/release/PROCESS.md`](docs/release/PROCESS.md) and [`docs/release/SUPPORT_MATRIX.md`](docs/release/SUPPORT_MATRIX.md). For the proposed in-process Git implementation, read [`docs/GIT_ENGINE.md`](docs/GIT_ENGINE.md).

## Non-negotiable architecture

- Sphinx is a synchronous local CLI. Do not add a listener, background lifecycle, remote Sphinx protocol, persistent identity cache, or local event log.
- The sole release target is cgo-enabled `darwin/arm64`.
- Tombs are Git repositories. Chambers are exact case-sensitive paths containing `artifact.yaml`.
- `.tomb/` is tomb metadata. `.sphinx/config.yaml` is consuming-project configuration.
- Runtime may execute only Git. age and SOPS are linked in process; Tailscale identity comes from LocalAPI.
- Every reveal performs a fresh live tailscaled identity check. There is no offline mode, override, or grace period.
- Decree enforcement is advisory for conforming Sphinx use. Do not represent it as a remote key-release boundary.
- Plaintext output is stdout only. Do not add clipboard, plaintext-file, temporary-file, dedicated-descriptor, or child-command output modes.
- Secret and proclamation authoring requires a controlling terminal. Do not accept private values through argv, stdin, files, general environment variables, or caller-provided descriptors.
- `SPHINX_GUARDIAN` is the sole read-only environment-provider record. It is captured once and removed before command parsing.
- Before command parsing or private-material loading, both macOS core-file limits must be set and verified as zero. Failure is closed with `security_control_failed`.
- Sphinx never initializes Git repositories or mutates Git history, branches, index, commits, tags, remotes, or transport state.
- Mutable operations require an explicit caller-managed `path:` worktree. Immutable caches are never edited.
- Multi-file mutations use exact path-scoped journals, guarded dependencies, atomic replacement, complete-state validation, and exact rollback. Never substitute broad Git recovery.
- Supported configuration, schema, artifact, decree, signature, and trust-transition versions are defined by `docs/ARCHITECTURE.md`. A new version requires an ADR, an explicit transition design where applicable, interoperability tests, and synchronized documentation.

## Cryptographic and format boundaries

- Native age suite: ML-KEM-768 + X25519 through `filippo.io/age` v1.3.1.
- SOPS: v3.12.1, one key group, exactly one proclamation recipient followed by zero or more unique guardian recipients.
- Signatures require both Ed25519 and ML-DSA-65 through CIRCL v1.6.1.
- Proclamations are generated ten-word phrases using the pinned 7,776-word list and fixed `argon2id-v1` parameters.
- Runtime must not invoke external cryptographic tools or plugins. External tools are test oracles only.
- All Sphinx YAML is strict UTF-8, LF-only, exactly one trailing LF, and one document.
- Reject unknown fields, duplicate keys, anchors, aliases, custom tags, merge keys, non-string mapping keys, and multiple documents.
- Artifact secrets and inscriptions are named non-null top-level string/integer/boolean scalars only.
- SOPS encrypts only `secrets`; readable inscriptions are unauthenticated until MAC verification.
- Managed tomb files must be exact regular Git blobs with no filters, LFS, encoding transforms, or line-ending transforms.
- Do not add Sphinx-defined size limits to artifacts, schemas, decrees, secrets, or repositories.

## Command and output contracts

The current command tree is defined in `docs/COMMANDS.md`. Global flags are:

- `--config`
- `--json`
- `--quiet`
- `--no-color`

JSON success is one newline-terminated version-1 object on stdout. JSON failure leaves stdout empty and writes one error object to stderr. Preserve stable BSD `sysexits` mappings in `internal/cli/result`.

Prompts use the controlling terminal so JSON streams remain clean. Never include secret values, proclamation text, or private identities in errors, warnings, logs, completion, or diagnostics.

## Package map

- `cmd/sphinx` — Cobra command surface and output behavior.
- `internal/artifact` — strict plaintext model and native SOPS engine; `internal/artifact/mutation` validates complete virtual mutation state.
- `internal/chamber`, `internal/locator` — chamber paths and tomb references.
- `internal/config`, `internal/git/env`, `internal/git/resource`, `internal/git/worktree` — project configuration, controlled Git execution, immutable Git content, and guarded caller-managed worktrees.
- `internal/decree`, `internal/tomb/state`, `internal/tomb/lock`, `internal/tomb/path`, `internal/tomb/transaction` — signed policy, locks, managed paths, trust transitions, and exact mutation transactions.
- `internal/guardian`, `internal/guardian/store`, `internal/guardian/keychain` — provider-authoritative guardian records.
- `internal/hybrid/age`, `internal/hybrid/sign`, `internal/proclamation` — fixed cryptographic boundaries; `internal/proclamation/rotation` coordinates credential rotation.
- `internal/seeker`, `internal/reveal` — live identity resolution and synchronous reveal coordination.
- `internal/safefile` — crash-safe atomic writes.
- `internal/yaml/strict`, `internal/schema` — shared strict YAML and schema validation.
- `internal/hardening` — macOS process controls.
- `internal/interoperability` — pinned external-oracle and known-answer tests.
- `internal/release/check` — repository examples, publication, and release-policy tests.

## Fixtures

- `testdata/interoperability/` contains pinned cryptographic vectors, a native hybrid identity, and external interoperability artifacts.
- `testdata/sops/` contains deterministic SOPS artifacts and test identities.

Committed private identities are test-only. Never load them from production code, copy them into examples/releases, or use them outside tests. Preserve fixture checksums when bytes are intentionally unchanged; update checksum assertions and fixture documentation together when an intentional fixture change is required.

## Development workflow

Use the Nix development environment on Apple Silicon:

```sh
nix develop
```

Fast focused checks:

```sh
go test ./path/to/package
go test -race ./path/to/package
go vet ./...
```

Complete repository gate:

```sh
./scripts/verify.sh
```

The complete gate performs formatting/tidiness, module verification, pinned external interoperability, all tests, all-package race tests, black-box CLI checks, deterministic fuzz smoke tests, static security scans, release-candidate validation, Nix flake checks, and diff hygiene.

Before finishing any change:

```sh
git diff --check
go test ./...
```

Run `./scripts/verify.sh` for changes affecting security boundaries, formats, commands, Git behavior, transactions, providers, cryptography, release metadata, or dependencies.

## Release workflow

`scripts/build-release-macos.sh VERSION` requires:

- a clean reviewed commit;
- `SPHINX_CODESIGN_IDENTITY`;
- `SPHINX_NOTARY_PROFILE`; and
- macOS Apple Silicon.

It invokes `scripts/verify.sh`, builds a system-linked arm64 PIE, rejects Nix-store dynamic-library paths, signs with hardened runtime and secure timestamp, notarizes and staples a signed disk image, verifies Gatekeeper acceptance, and emits checksums plus a CycloneDX SBOM.

Do not weaken clean-tree, signing, notarization, stapling, Gatekeeper, checksum, architecture, PIE, cgo, or system-library checks to make a release pass.

## Documentation organization

- Stable product documentation belongs under `docs/`, not the repository root.
- Format/configuration examples belong under `docs/examples/`.
- Test-only data belongs under purpose-named `testdata/` directories.
- Architectural rationale belongs in ADRs; normative behavior belongs in `docs/ARCHITECTURE.md`.
- Name folders, scripts, packages, fixtures, and status documents by enduring purpose.
- Keep Markdown links valid and update documentation in the same change as behavior.

## Change discipline

- Prefer narrow typed APIs and fail-closed validation.
- Preserve deterministic ordering and canonical encoding.
- Destroy or clear mutable sensitive buffers as early as practical; do not claim guaranteed erasure of Go strings.
- Keep errors descriptive but free of private values.
- Add adversarial tests for malformed input, symlink/special-file behavior, staged/unstaged Git conflicts, dependency changes, interrupted transactions, and output leakage when relevant.
- Never relax a security invariant solely to simplify a test or release step.
