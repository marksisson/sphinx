# Pure-Go Git Engine Plan

**Status:** Accepted by ADR 0009; implementation in progress

This document plans replacement of every production invocation of the Git executable with the current `main` branch of [`go-git`](https://github.com/go-git/go-git). Native Git remains a pinned test oracle until differential verification proves that the in-process implementation is equivalent or more conservative at every Sphinx trust boundary.

The implementation must preserve Sphinx's existing repository, lock, worktree, byte-integrity, and mutation invariants. It must not add Git authoring behavior: Sphinx still does not initialize repositories, create or switch branches, alter the index, commit, tag, merge, reset, modify remotes, push, or create linked worktrees.

## Research baseline and dependency policy

This plan was prepared against go-git `main` commit [`374c354884f12ea0a8f80ae9c429a44a33ba4bb1`](https://github.com/go-git/go-git/commit/374c354884f12ea0a8f80ae9c429a44a33ba4bb1), dated 2026-08-21.

Relevant upstream material:

- [`README.md`](https://github.com/go-git/go-git/blob/main/README.md)
- [`COMPATIBILITY.md`](https://github.com/go-git/go-git/blob/main/COMPATIBILITY.md)
- [`EXTENDING.md`](https://github.com/go-git/go-git/blob/main/EXTENDING.md)
- [`SECURITY.md`](https://github.com/go-git/go-git/blob/main/SECURITY.md)
- [`plumbing/format/gitattributes`](https://github.com/go-git/go-git/tree/main/plumbing/format/gitattributes)
- [`x/`](https://github.com/go-git/go-git/tree/main/x)
- [`x/plumbing/worktree`](https://github.com/go-git/go-git/tree/main/x/plumbing/worktree)

“Use main” means the repository follows go-git's `main` development line and may use its experimental APIs. A build must nevertheless be reproducible: `go.mod` and `go.sum` record the pseudo-version resolving to one exact commit, release evidence records that commit, and dependency updates are explicit reviewed changes. A floating branch is never resolved during a release build.

The researched main branch declares:

```text
module github.com/go-git/go-git/v6
go 1.26.0
```

Adoption therefore includes upgrading Sphinx's Go directive, Nix toolchain, release toolchain, CI assumptions, module checksums, SBOM expectations, and pinned external test environment to Go 1.26 or newer. The migration cannot merge while the release environment builds with an older toolchain.

Because `x/` explicitly permits API changes without semantic-version guarantees, every go-git commit update must run the complete differential suite and receive the same review as a security-boundary change. An update that changes experimental APIs, repository interpretation, transport behavior, object hashing, status, or attributes must not be treated as routine dependency maintenance.

## Required outcome

When this plan is complete:

- production Go code contains no `os/exec` use and does not search `PATH` for Git;
- the distributed application does not require a Git executable or wrapper;
- repository discovery, remote advertisement, materialization, object reads, ancestry, attributes, index inspection, and worktree status execute in process;
- native Git appears only in tests, fixture generation, and differential-oracle scripts;
- all existing exact-byte, fail-closed, no-history-mutation, no-index-mutation, and caller-managed-worktree guarantees remain true;
- unsupported repository, index, transport, attribute, or experimental-library behavior produces a stable fail-closed error before any tomb file is changed;
- the threat model, architecture, support matrix, SBOM, Nix package, and release verification describe the pure-Go boundary accurately.

## Non-goals

The feature does not use go-git to expose additional Git functionality. In particular, Sphinx will not use go-git to:

- initialize or clone a caller's writable tomb worktree;
- add, remove, initialize, prune, lock, or repair linked worktrees;
- stage paths or update an index;
- create commits, trees, tags, branches, or signatures;
- check out, reset, restore, stash, cherry-pick, rebase, merge, or resolve conflicts;
- update refs, remotes, or repository configuration;
- push or otherwise publish caller content;
- execute filters, Git hooks, credential helpers, pagers, editors, signing programs, or arbitrary SSH proxy commands;
- add LFS, submodule, partial-clone backfill, replacement-object, or promisor-object behavior.

These prohibitions apply even where go-git provides the capability.

## Upstream capability inventory

### Core library

go-git main provides both porcelain and plumbing APIs over filesystem and in-memory storage. The capabilities relevant to Sphinx include:

- filesystem and memory `Storer` implementations plus custom storage interfaces;
- `go-billy` filesystem abstraction;
- repository initialization and ordinary or mirror cloning;
- context-aware clone, fetch, and remote-reference advertisement;
- HTTP(S), SSH, `git://`, `file://`, and replaceable custom transports;
- unauthenticated, HTTP basic/token, private-key, and SSH-agent authentication primitives;
- OpenSSH known-host verification and selected SSH configuration resolution;
- refs, symbolic refs, branches, tags, HEAD, object iteration, and remote lists;
- commit, tree, blob, tag, and delta/pack object decoding;
- SHA-1 and SHA-256 repository object formats and protocol `object-format` negotiation;
- commit ancestry and merge-base APIs;
- mirror refspec support;
- worktree status, tracked/untracked state, ignore matching, and index decoding;
- Git index v2, including staged entries and merge stages;
- sparse checkout, shallow history, submodules, and filtered-fetch metadata;
- `gitattributes` parsing, recursive loading, macros, precedence-ordered matching, set/unset/unspecified/value states, and global/system attribute loaders;
- `gitignore` matching;
- local, global, system, and per-worktree configuration support;
- extension checks that reject unrecognized repository extensions when the storage backend cannot affirm support;
- configurable object caches, hash implementations, transports, storage, filesystems, compression, and config sources;
- bounded pack/index/reverse-index descriptor management and explicit idle-descriptor release.

The upstream compatibility matrix also identifies limits that matter to a fail-closed implementation:

- pack protocol v2 is not supported;
- index v1 and v3 are not supported, while index v2 is supported; other index formats and extensions require explicit verification;
- multi-pack-index and cruft-pack support is absent;
- replacement refs, reflogs, `fsck`, and several plumbing commands are absent;
- partial clone can record promisor packs but cannot fetch omitted objects on demand;
- merge is fast-forward only and many authoring commands are absent or partial;
- linked-worktree support is partial and experimental;
- sideband capabilities are partial;
- dumb HTTP is partial and requires filesystem-backed storage;
- Git LFS is not implemented.

Sphinx must not infer support from a high-level method merely existing. Every feature used by Sphinx needs an explicit acceptance test against the pinned commit.

### Experimental `x/` packages

The complete experimental surface examined for this plan is:

#### `x/plumbing/worktree`

Provides a `Worktree` manager backed by a storage implementation satisfying `x/storage.WorktreeStorer`:

- `New` creates the manager;
- `Open` opens a main or linked worktree;
- `List` lists linked-worktree names;
- `Add` creates metadata and checks out a linked worktree;
- `Remove` removes linked-worktree metadata;
- `Init` connects a filesystem to existing metadata;
- `WithCommit` and `WithDetachedHead` configure creation.

Sphinx will use only the read/open path. Calls to `Add`, `Remove`, or `Init` are forbidden. The implementation must account for the package's experimental metadata parsing, restricted worktree-name grammar, and 1,024-byte linked-worktree `.git` file read limit. Native-Git differential tests must cover worktrees created by Git itself, not only worktrees created by go-git.

#### `x/storage`

Adds experimental storage contracts:

- `ObjectFormatSetter` configures SHA-1 or SHA-256 object format on supporting stores;
- `ExtensionChecker` allows a store to affirm support for repository extensions and causes unknown extensions to fail;
- `WorktreeStorer` exposes the filesystem required by linked-worktree management.

Sphinx should rely on filesystem storage's extension checks rather than accepting unknown repository extensions. It must never change the object format of an existing repository.

#### `x/plugin` and `x/plugin/config`

Provides a typed, process-global plugin registry. Registration is replaceable until the first lookup and then freezes. Current plugin keys are:

- global/system config source;
- commit/tag object signer;
- zlib provider.

Config-source implementations include:

- `NewAuto`, which reads host global/system configuration using Git-like environment precedence;
- `NewStatic`, which supplies immutable caller-provided configuration;
- `NewEmpty`, which supplies no global or system configuration.

Sphinx must register `NewEmpty` before any go-git operation. This preserves the current isolation from global and system Git configuration. Repository and per-worktree configuration are read only when required to interpret repository structure. Sphinx must not register an object signer because it never creates Git commits or tags. The standard-library zlib provider remains in use unless a separately reviewed performance or security decision replaces it.

The pinned main commit's `plugin.Signer` accepts a `context.Context` and `io.Reader`. `EXTENDING.md` currently shows an older signature without the context argument; source code is authoritative when main-branch documentation and implementation differ. This discrepancy is an example of why source audit and compile-time pinning are required for every update.

#### `x/plugin/zlib`

Defines reader, writer, and provider contracts, a standard-library implementation, and registration-time provider validation. Sphinx does not need a custom provider initially.

#### `x/fdpool`

Provides a concurrency-safe fixed-capacity LRU pool for pack, index, and reverse-index descriptors. It supports pin hints, best-effort eviction, runtime statistics, disabled/no-op mode, and reuse across filesystem stores. Filesystem storage uses it directly.

Sphinx should configure an explicit bounded shared pool for repository/cache readers and close repositories and idle descriptors deterministically. Eviction must affect performance only; it must not impose a repository-size acceptance limit.

## Current Sphinx Git operations and replacements

| Current native Git behavior | Current location | Planned go-git implementation |
|---|---|---|
| discover nearest worktree root | `internal/config`, `internal/locator` | shared read-only worktree opener with parent discovery and exact-root validation |
| reject bare repositories | `internal/config`, `internal/locator` | repository/worktree presence checks and filesystem-storage metadata validation |
| obtain absolute Git directory and common directory | `internal/git/repository`, consumed by `internal/config`, `internal/locator`, and `internal/git/worktree` | filesystem storage plus `x/plumbing/worktree` metadata resolution, followed by Sphinx symlink/canonical-path checks |
| resolve local `HEAD^{commit}` | `internal/git/resource` | resolve HEAD, peel symbolic/tag references as allowed, and require a commit object with the repository's object format |
| `ls-remote` exact HEAD/branch/tag advertisement | `internal/git/resource` | context-aware remote `List` with exact ref-name matching and explicit annotated-tag peeling |
| reject same-name branch/tag ambiguity | `internal/git/resource` | inspect the complete advertised ref set before choosing a commit |
| mirror clone into a candidate cache | `internal/git/resource` | context-aware filesystem-backed mirror clone into the existing private candidate directory |
| verify an approved commit exists | `internal/git/resource` | parse the full object ID using the repository format and load the exact commit object |
| list committed trees recursively | `internal/git/resource` | traverse exact commit trees without checkout, preserving modes, names, case, and raw content |
| read exact committed blobs | `internal/git/resource` | load blob objects directly from storage and read their exact bytes |
| test commit ancestry | `internal/git/resource` | commit `IsAncestor` or equivalent graph traversal with explicit missing-object failure |
| evaluate committed attributes | `internal/git/resource` | build a matcher from `.gitattributes` blobs at the exact commit and query only guarded attributes |
| reject in-progress operations | `internal/git/worktree` | continue direct, no-follow inspection of worktree/common administrative markers |
| detect unmerged entries | `internal/git/worktree` | decode the exact index and reject every entry whose raw stage bits are nonzero |
| target-scoped staged/unstaged/untracked status | `internal/git/worktree` | compare HEAD, index, and filesystem for each literal canonical target; use go-git status only after parity is demonstrated |
| evaluate worktree and HEAD attributes | `internal/git/worktree` | separate matchers for current filesystem attributes and exact HEAD-tree attributes, plus applicable info attributes |
| compare raw and prospective blob IDs | `internal/git/worktree` | after proving all transformations absent, hash `blob <length>\0<bytes>` with go-git's repository-format-aware hasher and require the raw and prospective models to agree |
| prevent ambient Git configuration | `internal/git/runtime` | register and freeze `x/plugin/config.NewEmpty` before first go-git use |

No production package outside `internal/git` should import go-git directly. `internal/config`, `internal/locator`, and mutation-facing `internal/git/worktree` consume the narrow read-only discovery interface from `internal/git/repository`. This avoids an import cycle between locator parsing and mutation worktrees while keeping experimental API churn and repository parsing inside one trust boundary.

## Proposed architecture

### Process-global initialization

Add a small `internal/git/runtime` package responsible for one-time initialization before any repository is opened:

- register `x/plugin/config.NewEmpty` for global and system scopes;
- retain the standard zlib provider;
- create the bounded shared `x/fdpool.Pool` used by filesystem stores;
- expose the pinned upstream commit as build/test metadata;
- fail immediately if plugin registration has already frozen or was replaced unexpectedly.

Initialization must happen explicitly from application startup and test setup, not through ambiguous import-order side effects. Tests must prove that global/system config, `GIT_CONFIG_*`, and hostile user configuration cannot alter refs, attributes, transports, object directories, or worktree interpretation.

### Repository opening

Create one internal opener that returns a read-only handle containing:

- canonical worktree root when present;
- canonical worktree-specific Git directory;
- canonical common Git directory;
- filesystem storage and repository handles;
- detected object format;
- index handle when a worktree is present;
- deterministic close behavior.

The opener must:

- use no-follow `Lstat` and canonical-path validation around all paths derived from repository metadata;
- reject a path that is not exactly the selected worktree root when exact-root semantics are required;
- support main and native-Git-created linked worktrees through `x/plumbing/worktree`;
- reject bare repositories for mutable `path:` operations while permitting bare immutable caches;
- reject unknown extensions, unsupported index versions, unsafe alternates, malformed `.git` files, missing common directories, and repository-format disagreement;
- never repair, initialize, migrate, or write repository metadata;
- close storage, pack readers, and idle descriptors on every return path.

### Remote transport

Only the locator's existing schemes remain accepted:

- `github:` resolves to HTTPS;
- `git+https://` uses smart HTTPS, with dumb HTTP accepted only if differential tests demonstrate exact and safe behavior;
- `git+ssh://` uses go-git's SSH transport;
- `path:` stays local;
- `git://`, `file://`, arbitrary custom schemes, embedded passwords, and URL fragments remain rejected.

Transport policy must be explicit rather than inheriting all go-git defaults:

- contexts cancel DNS, dialing, negotiation, and object transfer;
- TLS verification is mandatory and no insecure custom transport is registered;
- SSH host-key verification is mandatory;
- SSH agent use is permitted;
- user and system SSH configuration is not loaded; host, user, and port come only from the canonical URL, so routing, identity, proxy, and command directives cannot alter transport;
- no interactive password prompt is introduced;
- no credential helper or arbitrary helper subprocess is executed;
- redirects must not forward credentials across hosts;
- transfer errors must not leak URL user information or authentication material.

The pinned `ssh.NewSSHAgentAuth` discards the distinct SSH-agent `net.Conn` returned by its agent dialer and exposes no close operation. Closing the Git SSH client or session does not close that agent socket. Production transport must therefore own the agent connection through a narrow authentication wrapper and defer its close immediately after a successful dial, alongside the transport-managed Git SSH client and session lifecycle. The isolated SSH oracle demonstrates this ownership pattern.

ADR 0009 selects anonymous verified HTTPS and SSH-agent-only authentication with standard known-host files. Native-Git credential helpers, `.netrc`, `IdentityFile`, `ProxyJump`, `ProxyCommand`, SSH host aliases, password authentication, and ambient proxy routing are outside the supported contract.

### Immutable object cache

Retain Sphinx's existing cache ownership rather than delegating lifecycle policy to go-git:

1. derive the cache key from canonical repository identity and approved commit;
2. take the existing no-follow interprocess lock;
3. validate an existing entry as a non-symlink bare repository containing the exact commit;
4. evict an invalid entry;
5. mirror-clone into a private candidate path;
6. verify object format, exact approved commit, managed tree entries, attributes, and required blobs;
7. synchronize candidate contents;
8. atomically promote and synchronize the parent directory.

Do not use in-memory clone storage for production caches. Filesystem storage is required for bounded memory, durable promotion, reopening, dumb-HTTP compatibility where allowed, and release diagnostics. Partial clone and promisor-object behavior are prohibited because missing objects cannot be fetched on demand and exact locked validation must be self-contained.

### Exact object and path handling

The engine must preserve Git tree semantics rather than normalize through host filesystem semantics:

- traverse the locked commit tree directly;
- preserve case-distinct paths even on case-insensitive macOS filesystems;
- compare path bytes exactly before applying Sphinx's UTF-8 chamber/schema grammar;
- reject NUL, malformed, duplicate, ambiguous, or noncanonical managed paths;
- accept managed entries only with regular blob modes `100644` or `100755`;
- reject symlink mode `120000`, gitlink mode `160000`, trees where blobs are required, and LFS pointer content;
- calculate Sphinx locks as SHA-256 over exact blob bytes independently of Git's SHA-1 or SHA-256 object format;
- reject replacement refs and object alternates that could make validation depend on mutable external storage;
- reject missing promisor objects rather than attempting lazy network access.

Differential fixtures must include invalid UTF-8 tree names, case collisions, unusual but valid ref names, annotated and lightweight tags, SHA-1 and SHA-256 repositories, packed and loose objects, shallow repositories, and malicious modes.

### Attribute evaluation and prospective bytes

Implement an internal effective-attribute evaluator over go-git's `plumbing/format/gitattributes`:

- use `x/plugin/config.NewEmpty` so no global/system attribute path is inherited;
- for immutable reads, load `.gitattributes` from the exact commit tree along the managed path's ancestor chain;
- for mutable checks, independently evaluate the current worktree files and the exact HEAD tree;
- include `.git/info/attributes` only with the same precedence and scope as native Git, after validating its location and file type;
- allow macros only where Git allows them;
- retain source order and root-to-leaf precedence exactly;
- query `filter`, `working-tree-encoding`, `text`, and `eol`;
- accept only `unspecified`, plus explicitly unset `text`;
- reject every set, value-set, malformed, unsupported, or indeterminate transformation attribute;
- reject LFS pointers independently of attribute state.

Sphinx does not need to execute a clean filter. Once both worktree and HEAD evaluations prove that transforms are absent, the prospective committed bytes are the exact regular-file bytes. Compute the repository object ID using go-git's object-format-aware hasher as a defense-in-depth check while continuing to return Sphinx's SHA-256 content digest.

A native-Git oracle test must compare every matcher result and prospective object ID with `git check-attr -z` and `git hash-object` across nested attributes, macros, negation, quoting, Unicode, info attributes, EOL settings, filter drivers, and SHA-1/SHA-256 repositories.

The pinned `gitattributes.Matcher` does not preserve native first-match precedence when one call spans multiple matching rules: lower-priority rules can overwrite an attribute already returned by a higher-priority rule. The differential adapter therefore evaluates each rule from highest to lowest priority and accepts the first state for each queried attribute while retaining the complete macro-definition stack. Production attribute evaluation must preserve this workaround unless a reviewed go-git update fixes the behavior and the oracle matrix proves parity.

### Worktree and index safety

Use `x/plumbing/worktree` only to open and inspect existing worktrees. Preserve the Sphinx `Worktree` and `Guard` APIs so transaction and domain code do not depend directly on experimental types.

For every mutable operation:

- require an explicit canonical `path:` root;
- reject cache paths, symlink traversal, bare repositories, malformed linked metadata, and unsupported repository extensions;
- read the correct linked-worktree index and per-worktree configuration;
- reject unsupported index versions and extensions;
- inspect raw index stage bits and reject all nonzero stages;
- reject merge, rebase, cherry-pick, and revert markers in both worktree-specific and common administrative directories;
- determine target-scoped staged, unstaged, deleted, and untracked state without changing index timestamps or extensions;
- retain the narrow editable-input exception for decree and schema authoring while rejecting staged editable inputs;
- snapshot exact target bytes, modes, size, modification time, and digest;
- rerun administrative checks and snapshots at existing TOCTOU barriers;
- never call go-git methods that write index, refs, config, checkout state, or worktree metadata.

The differential matrix must include main worktrees and linked worktrees created by native Git; detached HEAD; unborn branches; split/common metadata; staged/unstaged/type/mode changes; untracked files; intent-to-add; skip-worktree and assume-unchanged bits; conflicts at stages 1/2/3; index v2 and unsupported index versions; sparse checkout; nested repositories; case-only names; and every operation marker.

The pinned main source currently defines the exported `index.Merged` constant with value `1`, while ordinary fully merged entries use raw stage bits `0`. Sphinx must not rely on that constant. It must inspect decoded raw stage values and differential-test ordinary and conflicted indexes. Any upstream correction requires a reviewed dependency update.

## Implementation workstreams and gates

The work is organized by independently reviewable capability gates rather than by allowing a mixed production backend indefinitely.

### Dependency and toolchain gate

- resolve go-git `main` to the reviewed commit and add the resulting pseudo-version and checksums;
- upgrade Sphinx and Nix to Go 1.26 or newer;
- regenerate the vendor hash and SBOM expectations;
- audit new direct and transitive dependencies, licenses, advisories, cgo use, and dynamic linkage;
- run all current crypto interoperability vectors after minimal-version selection upgrades;
- add a test that records and checks the selected go-git commit used by the build.

Exit condition: existing Sphinx behavior and release-candidate verification pass with go-git linked but no production Git behavior changed.

### Differential oracle gate

Create test-only adapters implementing every required operation with:

- the current native Git commands;
- the proposed go-git implementation.

Generate identical repositories once, execute both adapters against immutable copies, and compare structured results rather than error strings. Classify each case as:

- equivalent success;
- go-git conservative rejection of a case outside the supported contract;
- unacceptable disagreement.

Native Git versions used as oracles remain pinned in `scripts/verify.sh`. No production fallback from go-git to native Git is allowed.

Exit condition: the differential suite covers every row in the operation table and every adversarial matrix in this plan.

### Read-only repository gate

**Status:** Implemented in the current tree. `internal/git/resource` contains no native-Git execution path; a release-policy test enforces that boundary. Transport-policy hardening remains governed by the later transport and authentication gate.

Migrate remote listing, mirror materialization, commit verification, tree/blob reads, object-format handling, ancestry, and immutable attributes inside `internal/git/resource`.

Keep the current cache lock, candidate, synchronization, promotion, corruption eviction, and exact-content validation logic. Remove only the subprocess implementation.

Exit condition: reveal, inspect, public validation, enrollment, and lock-update tests pass with no production Git invocation for immutable resources.

### Worktree discovery gate

**Status:** Implemented in the current tree. Shared discovery lives in `internal/git/repository`; release-policy tests prevent native root or administrative-directory discovery from returning.

Migrate root discovery in `internal/config` and `internal/locator`, and administrative-directory discovery in `internal/git/worktree`, to the shared opener and `x/plumbing/worktree`.

Exit condition: main, nested, detached, and linked worktrees created by native Git resolve to exactly the same canonical roots and administrative directories, and malformed metadata fails closed.

### Mutation-safety gate

**Status:** Implemented in the current tree. `internal/git/worktree` contains no native-Git execution path; release-policy tests enforce that boundary. Index versions other than v2, including v3 files produced for intent-to-add and skip-worktree entries, are conservatively rejected. Assume-unchanged does not suppress Sphinx's go-git worktree comparison, so hidden target changes are also conservatively rejected.

Migrate index conflict detection, target status, attribute checks, and prospective-object hashing. Retain direct marker and filesystem safety checks.

Exit condition: every mutation, crash-recovery, TOCTOU, symlink, attributes, and status test passes without production Git invocation and without any repository/index metadata change.

### Transport and authentication gate

**Status:** Implemented in the current tree. `internal/git/transport` centralizes anonymous smart HTTPS and SSH-agent-only policy, owns agent and HTTP lifecycles, ignores ambient proxy and SSH routing configuration, requires TLS and known-host verification, bounds redirects, propagates cancellation through SSH handshake connections, and emits redacted transport diagnostics.

Implement the accepted HTTPS and SSH credential policy, known-host verification, SSH configuration handling, redirects, cancellation, and error redaction. Add local protocol servers and isolated SSH-agent fixtures; official tests must not depend on public GitHub availability.

Exit condition: public and supported private transports work noninteractively, unsupported auth/configuration fails with stable diagnostics, and no secret reaches argv, environment diagnostics, or persisted configuration.

### Removal and publication gate

**Status:** Implemented in the current tree. Production Go code has no external-process path, runtime packaging does not include or wrap Git, native-oracle environment isolation lives under `internal/testgit`, verification rejects regressions, and release candidates execute with an empty `PATH`.

- delete `internal/git/env` and all production subprocess helpers;
- remove Git from the distributed Nix wrapper and runtime requirements;
- retain Git in development and verification environments solely as an oracle;
- make `scripts/verify.sh` fail if non-test Go code imports `os/exec` or invokes an external process;
- update `docs/ARCHITECTURE.md`, `docs/PRD.md`, `AGENTS.md`, threat model, support matrix, release process, and package comments;
- update release checks to prove the executable runs with an empty `PATH`;
- regenerate SBOM and release-candidate evidence.

Exit condition: the complete verification gate passes and the candidate binary performs representative local and remote Git operations without a Git executable present.

## Required tests

At minimum, the final suite must cover:

### Repository formats and storage

- SHA-1 and SHA-256 repositories;
- loose, packed, and mixed object storage;
- annotated and lightweight tags;
- symbolic and detached HEAD;
- shallow history;
- corrupt objects, packs, indexes, refs, and config;
- unknown extensions, alternates, replace refs, promisor packs, and missing objects;
- bounded file-descriptor behavior under many packs and concurrent reads;
- cache races, corruption eviction, cancellation, and atomic promotion.

### Paths and tree entries

- case-colliding committed paths on case-insensitive macOS;
- invalid UTF-8 and quoted path bytes;
- symlink, gitlink, tree, executable blob, and ordinary blob modes;
- LFS pointer detection;
- exact chamber and schema lookup without checkout;
- pathspec-like characters treated literally;
- empty, duplicate, missing, and ambiguous entries.

### Attributes

- root and nested `.gitattributes` precedence;
- macros and macro-placement errors;
- set, unset, unspecified, and valued attributes;
- `.git/info/attributes` precedence;
- current-worktree versus HEAD disagreement;
- filter, LFS filter, text, eol, and `working-tree-encoding` combinations;
- quoted, escaped, Unicode, and malformed patterns;
- parity with native `check-attr` and `hash-object`.

### Worktrees and indexes

- main and native-created linked worktrees;
- nearest-root discovery from nested directories;
- detached and unborn HEAD;
- per-worktree config;
- staged, unstaged, deleted, untracked, mode, and type changes;
- editable authoring inputs;
- conflict stages and operation markers;
- unsupported index versions/extensions;
- symlinked metadata and worktree components;
- simultaneous caller edits at each TOCTOU boundary;
- proof that refs, HEAD, index, config, remotes, and worktree metadata are byte-identical before and after Sphinx operations.

### Transport

- smart HTTPS and SSH;
- authentication success/failure for every supported provider;
- mandatory TLS and SSH host verification;
- unknown and changed host keys;
- redirect credential stripping;
- cancellation during DNS, connection, advertisement, and pack transfer;
- malformed advertisements, oversized sideband messages, truncated packs, and object-format mismatch;
- branch/tag ambiguity and annotated-tag peeling;
- unsupported proxy/config/auth features failing closed.

### Runtime isolation

- empty `PATH` success for commands using local repositories;
- no production `os/exec` imports or subprocess calls;
- hostile global/system Git config has no effect;
- no hooks, filters, pagers, editors, signing tools, credential helpers, or SSH commands execute;
- errors and JSON envelopes preserve stable classifications without leaking URLs or credentials.

## Security review questions

The implementation review must answer explicitly:

1. Can any repository-controlled config cause code execution, network redirection, object substitution, or reads outside approved roots?
2. Can go-git write repository, index, refs, config, or worktree metadata merely by opening, reading status, or closing?
3. Are all storages, object readers, pack readers, transports, and SSH-agent connections closed on cancellation and error?
4. Are global plugin registrations deterministic, immutable after startup, and tested against initialization-order mistakes?
5. Does every unsupported format or extension fail before any caller-managed file changes?
6. Are object IDs parsed with the repository's actual format while Sphinx content locks remain independent SHA-256 digests?
7. Can attribute parsing or ignored unsupported directives cause transformed bytes to be accepted as exact bytes?
8. Can linked-worktree metadata escape the selected repository through relative paths or symlinks?
9. Does transport authentication preserve host verification and avoid interactive or subprocess-based secret handling?
10. Does following go-git main introduce an unreviewed semantic change between source verification and release construction?

## Documentation and decision records

Before production cutover:

- add an ADR selecting go-git main, experimental API policy, supported repository formats, and transport/authentication contract;
- revise the architecture statement that Sphinx may invoke Git to instead specify the in-process Git engine;
- document conservative rejections in the support matrix;
- update the threat model for parser, packfile, transport, plugin-registry, SSH-agent, and experimental-API risks;
- update release documentation to record the go-git commit and prove no Git executable is packaged or required;
- update `AGENTS.md` with the go-git boundary and dependency-update discipline.

This plan is complete only when the native Git executable is an external test oracle and no longer part of Sphinx's production runtime or package wrapper.
