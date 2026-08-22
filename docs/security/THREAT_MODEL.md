# Threat-model review

Date: 2026-08-22

Scope: the initial Sphinx CLI release on macOS Apple Silicon. This review follows data from controlling-terminal entry and credential-provider retrieval through authorization, decryption, output, mutation, and crash recovery. It does not treat advisory decree policy as a cryptographic barrier against a person who already possesses a recipient identity.

## Security boundaries

Trusted boundaries are the Sphinx executable, the current process address space, macOS Keychain, local tailscaled LocalAPI, the pinned in-process go-git engine, system TLS roots and SSH known-host trust, and the caller-controlled terminal/stdout destination. Tomb contents, consuming-project configuration, worktrees, caches, environment records, repository refs, remote protocol responses, and all YAML are untrusted inputs.

The release does not claim protection from a compromised user account, debugger or root access, malicious terminal emulator, compromised tailscaled, compromised credential provider, substituted signed executable, or a guardian holder using native SOPS/age outside Sphinx.

## Findings and controls

### Local authorization bypass

**Residual risk: accepted and explicit.** Decrees are advisory policy for conforming Sphinx use. A guardian identity can decrypt its recipient artifacts outside Sphinx and bypass seeker policy. Sphinx therefore makes no key-release or remote-enforcement claim.

Within the CLI, every reveal performs a fresh tailscaled LocalAPI status request, verifies login/tag allow rules, verifies the externally pinned proclamation fingerprint and decree generation, checks exhaustive committed Git blob locks, selects an eligible configured guardian, then verifies recipient wrapping, SOPS MAC, and schema before output. There is no offline identity cache, override, grace period, alternate output command, or network endpoint.

### Proclamation entropy and offline guessing

**Risk: controlled.** New proclamations contain ten independently selected words from the pinned 7,776-word list, approximately 129 bits before derivation. Derivation uses the fixed `argon2id-v1` profile: Argon2id v0x13, 256 MiB, three iterations, four lanes, a per-tomb random 32-byte salt, and a 32-byte output followed by domain-separated HKDF derivation. Prompting is controlling-terminal-only with three attempts. There is intentionally no claim of persistent online rate limiting; an attacker with signed public state can perform offline guesses, making generation entropy essential.

### Dependency and cryptographic integrity

**Risk: controlled with a pinned supply chain.** `go.mod`, `go.sum`, `flake.lock`, the Nix fixed vendor hash, pinned-version tests, fixture checksums, and independent native age/SOPS interoperability tests pin and exercise age v1.3.1, SOPS v3.12.1, CIRCL v1.6.3, the reviewed go-git commit, and their module graph. Runtime executes no age/SOPS executable or plugin. Release builds use the locked Nix input or the checked module sums, `-trimpath`, PIE, cgo, and the exact `darwin/arm64` target. The release procedure records checksums, build information, an SBOM, signing verification, notarization status, and Gatekeeper assessment.

A malicious upstream source accepted into a future dependency update remains a supply-chain risk. Updates require review, checksum/vendor-hash changes, interoperability vectors, the complete verification gate, and a new signed/notarized artifact.

### Git locks, mutable refs, and local worktrees

**Risk: controlled.** Remote refs are resolved once to full commits; prepared updates are descendant-only and install the exact prepared commit. Locked reads use exact Git blobs rather than worktree files. Managed blobs reject submodules, filters, LFS transformations, encoding, and line-ending transformations. Repository discovery, object access, status, attributes, hashing, and transport execute in process through the pinned go-git engine with isolated ambient Git configuration and bounded shared descriptors.

Remote transport is deliberately narrow: anonymous verified smart HTTPS uses system roots, direct dialing, initial-request redirects, and no credential source; SSH uses only the caller's agent plus standard known-host files and ignores SSH routing/identity configuration. Cross-authority redirects strip sensitive headers, TLS downgrades and dumb HTTP fail closed, SSH handshakes are context-bound, and diagnostics redact upstream details. A compromised user account can still replace its own TLS/known-host trust or agent and remains outside the threat model.

Explicit `path:` worktrees are the only mutable target. Before administrative mutation, complete managed state must be clean, signed state must verify, dependencies are read-only and guarded, edited paths are explicit, and pre/post images are validated. Sphinx never mutates Git history or the index. Native Git is a pinned test oracle only and is not a production fallback.

### Recipient mutation and proclamation rotation

**Risk: controlled.** Artifacts permit exactly one leading proclamation recipient and zero or more unique native hybrid guardian recipients. Adding/removing guardians, inscription changes, reseals, and proclamation rotation create fresh independent artifact data keys and fully re-encrypt affected artifacts. Every mutation updates exhaustive locks and increments the signed decree generation exactly once.

Proclamation rotation is an atomic all-artifact transition. The append-only record is cross-signed by old and new proclamations, all artifacts move to only the new proclamation recipient, and the manifest/decree/signature transition installs in one journaled transaction. Existing rotation blobs are immutable guarded dependencies. Mixed-suite or partial rotation is rejected.

### Plaintext and private-material leakage

**Risk: reduced, not eliminated from process memory or the chosen output sink.** Secrets and proclamations are read only from a controlling terminal. No secret/proclamation value is accepted in argv, ordinary stdin, caller file descriptors, files, command completion, or flags. This keeps values out of normal shell history and argv-based process listings. Decrypted output is stdout only; terminal output requires a warning and approval. JSON puts plaintext only below `data.secrets`. Handled errors and warnings contain no secret values.

Before any command body runs, Sphinx sets and verifies both soft and hard macOS `RLIMIT_CORE` values as zero. Failure returns `security_control_failed` before command execution. The read-only `SPHINX_GUARDIAN` provider is the one explicit environment secret boundary; application initialization captures it once and removes the variable before command parsing so child processes and later common environment inspection cannot recover it. Environment bytes and Go strings may still have process-memory remnants.

Sphinx creates no plaintext temporary file, clipboard content, dedicated output descriptor, subprocess environment, local event log, or debug log. Journals contain exact encrypted/metadata pre/post images, never decrypted documents. Mutable byte buffers and identity records are cleared/destroyed where practical, but Go does not guarantee erasure of immutable string backing memory. stdout redirection, terminal scrollback, shell pipeline consumers, screen capture, swap, debuggers, and a compromised process remain caller/OS risks.

### Transaction rollback and signed-state rollback

**Risk: controlled.** Multi-file mutation journals live below the Git administrative directory, use no-follow locking and atomic replacement, name exact targets, and contain validated pre/post images. Installation rechecks guarded dependencies and target preimages. Recovery accepts only exact pre-state rollback or exact complete post-state; ambiguous, missing, or corrupt journals fail closed and require caller-managed path-scoped Git recovery. Sphinx never uses broad Git reset/restore operations.

Consuming locks pin commit, proclamation fingerprint, and decree generation. Updates require descendant commits. Same-generation state must be byte-identical; authorized mutation increments generation. Cross-signed proclamation transitions preserve trust continuity. A caller can still deliberately replace its own consuming configuration with an older lock; protecting project configuration and review history is outside Sphinx's local advisory boundary.

## Review conclusion

No release-blocking design contradiction was found in the implemented trust model. The most important residual risks are intentional: guardian holders can bypass advisory seeker policy, plaintext security ends at stdout, environment-provider identities have process-memory exposure, pinned go-git and remote parsers remain dependency boundaries, tailscaled/Keychain and local transport trust are external dependencies, and privileged local compromise defeats process controls. These limitations are stated in release and operational documentation rather than represented as guarantees.
