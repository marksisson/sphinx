# Phase 2 implementation record

Phase 2 establishes deterministic repository, lock, and worktree boundaries. The replacement command tree consumes these APIs in Phase 6; discarded MVP commands are not compatibility interfaces.

## Tomb references and chambers

- `internal/locator` now accepts only `github:`, `git+https://`, `git+ssh://`, and explicit `path:` references.
- Remote references permit at most one mutually exclusive `?ref=` or `?rev=` selector. Legacy path-in-repository selectors and implicit filesystem paths are rejected.
- `path:` references resolve to the exact root of an existing non-bare Git worktree and reject symlink traversal.
- `internal/chamber` preserves exact ASCII case and always derives `CHAMBER/artifact.yaml`.

## Configuration and approval locks

- `internal/config` implements optional, read-only XDG global aliases and strict Git-root `.sphinx/config.yaml` project configuration.
- Omitted tomb selection means the alias exactly `default`; no single-tomb fallback exists.
- Enrollment supports exact global aliases, direct canonical references, explicit name overrides, and repository-basename defaults.
- Project locks contain the exact commit, proclamation fingerprint, unsigned decree generation, UTC lock timestamp, and ordered guardian selections.
- Canonical duplicate references, ambiguous names, unsafe ownership/types, symlinked configuration, unknown YAML fields, and legacy settings are rejected.
- Project writes use a Git-administrative inter-process lock and one crash-safe atomic replacement. Multi-tomb lock proposals validate completely before one all-or-nothing write.

## Immutable Git resources

- `internal/gitresource` materializes bare object databases under the XDG cache with per-entry inter-process locking, candidate directories, recursive synchronization, atomic promotion, corruption eviction, and exact repository-plus-commit cache keys.
- Locked reads use `git ls-tree` and `git cat-file` directly; no immutable checkout exists.
- Public content validation requires canonical `.tomb/` metadata, the zero-byte rotation sentinel, canonical tomb-local schemas, and exact-case chamber artifacts.
- Every managed entry must be a regular Git blob with strict YAML syntax and no LFS pointer, filter, working-tree encoding, or line-ending transformation attributes.
- Schema contents must match their exact `.tomb/schemas/name/vN.yaml` path. Alternate metadata, symlinks, and submodules are rejected.
- Mutable lock preparation resolves an exact candidate commit, requires descendant history, validates all candidate content, and preserves the prepared commit if the ref moves before installation.

## Writable worktrees

- `internal/worktree` accepts only explicit caller-managed `path:` roots and rejects remote references and immutable caches.
- Mutation guards reject in-progress Git operations, unmerged entries, dirty target paths, unsafe attributes, traversal, and symlinks while allowing unrelated dirty files.
- Guards retain exact pre-validation state for TOCTOU revalidation.
- Prospective managed-blob hashing verifies that Git filters would not transform bytes and computes SHA-256 over the exact file bytes.
- These APIs execute no Git initialization, staging, commit, ref mutation, branch operation, push, reset, restore, or merge command.

## Deterministic resolution

`internal/lockedresource` combines a strict project lock, canonical tomb reference, exact chamber, immutable object cache, and validated tomb content. Its result is exactly one approved `CHAMBER/artifact.yaml` blob plus schemas from the same commit.

Tests cover malformed references, selectors, aliases, default behavior, project-root and nested-worktree discovery, config races, all-or-nothing lock updates, cache races/corruption, mutable-ref movement, non-descendant history, dirty targets, Git operation markers, symlinks, submodules, LFS and transformation attributes, strict YAML, exact blob bytes, TOCTOU, exact case, and case-colliding Git chambers.
