# Phase 7 implementation record

Phase 7 removes the superseded implementation and makes the repository describe and build only the initial synchronous CLI release.

## Deleted implementation

The following unreachable MVP trees were deleted in full rather than retained behind compatibility adapters:

- `internal/audit`
- `internal/identity`
- `internal/policy`
- `internal/relic`
- `internal/secret`
- `internal/server`
- `internal/tomb`
- the unused `internal/tombref` forwarding wrapper

Their tests, classical X25519/recovery envelope, HTTP handlers, persistent event writer, old Tailscale identity glue, old path policy, filesystem format, configuration wrappers, and repository helpers were removed with them. The LaunchAgent example and obsolete security-comparison HTML were also deleted. No migration reader, old-format fixture, conversion command, network lifecycle file, unused forwarding wrapper, or compatibility package remains.

The production package graph now consists only of the Phase 1–6 boundaries: strict YAML, canonical artifacts/chambers/schemas, native hybrid cryptography and signatures, proclamation/guardian providers, immutable Git resources and project locks, signed tomb state/decrees, fresh seeker resolution, reveal, mutation transactions, recovery, rotation, safe files, and the final CLI.

## Local path commit resolution

`gitresource.ResolveCommit` now resolves an explicit selector-free `path:` worktree with isolated `git -C WORKTREE rev-parse --verify HEAD^{commit}` rather than treating it as a transport URL. This keeps local administrative mutation network-independent, works in the restricted Nix check environment, and still returns only a full lowercase commit ID. Remote references retain single-resolution `ls-remote`; impossible synthetic path locators containing selectors retain ambiguity checks. Direct and CLI-level regression tests cover the local behavior.

## Documentation and examples

The following files were rewritten for the initial format and final vocabulary:

- `README.md`
- `docs/PRD.md`
- `docs/SCHEMAS.md`
- `docs/TERMINOLOGY.md`
- `decree.example.yaml`
- `schema.example.yaml`
- `sphinx.example.yaml`
- `global.example.yaml`

They now document only CLI operation, exact Git tombs, `.tomb/` metadata, `.sphinx/config.yaml` project locks, live local tailscaled identity, signed allow-only decrees, strict tomb-local schemas, proclamation/guardian recipients, controlling-terminal authoring, stdout-only plaintext, path-scoped transactions, and advisory policy limits. Current documentation and metadata pass a case-insensitive retired-vocabulary gate. Historical redesign records and accepted ADR rationale remain explicit about what was deleted.

The examples are executable format fixtures: Phase 7 tests parse the schema and complete decree through strict domain decoders, parse the project configuration, and load the manually managed global alias file through the normal safety boundary.

## Dependencies and release metadata

`go mod tidy` removed packages reachable only through the deleted implementation. Remaining large provider dependency subtrees are transitive requirements of pinned SOPS v3.12.1 and are not runtime-selected recipient mechanisms.

`flake.nix` now exports packages, apps, checks, development shell, and formatter only for `aarch64-darwin`. Package metadata describes the final artifact model. Git is available during the package test phase and wrapped into the runtime path because repository operations are required. The fixed Go vendor hash was regenerated from the current module graph.

Running plain `nix flake check` against a dirty Git worktree omits untracked Phase 1–7 files by Git-source semantics. The gate therefore uses `nix flake check path:$PWD`; this includes the complete working tree and successfully builds and tests the native Apple Silicon package. Once the files are committed, the ordinary Git flake source is equivalent.

## Verification

`internal/phase7/phase7_test.go` verifies strict example decoding, absence of every deleted tree/deployment artifact, the Apple-Silicon-only output matrix, and final command documentation.

`scripts/verify-phase7.sh` verifies:

- deleted paths and package imports remain absent;
- current release documentation, examples, metadata, and production Go contain no retired vocabulary;
- production Go has no HTTP/listener or remote-peer `WhoIs` boundary;
- the package output matrix is exactly `aarch64-darwin`;
- `go mod tidy` and `gofmt` complete cleanly;
- all Go tests pass;
- race tests pass across every Go package;
- chamber and tomb-reference fuzz targets run successfully;
- `go vet ./...` passes;
- the complete Apple Silicon package builds and tests through `nix flake check path:$PWD`; and
- `git diff --check` passes.
