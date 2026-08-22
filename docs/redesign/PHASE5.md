# Phase 5 implementation record

Phase 5 establishes the signed decree/trust boundary, current-local-seeker authorization, synchronous guardian reveal coordinator, monotonic project-lock advancement, and complete proclamation rotation. Phase 6 binds these typed APIs to the final command tree and output contracts.

## Strict allow-only decrees

`internal/decree` owns the strict version-1 plaintext policy.

- `generation` is a required positive `uint64`; zero, negative, overflow, omitted, or alternate numeric forms fail.
- `artifact_locks` and `schema_locks` are required, exhaustive inputs to validation, unique, bytewise sorted, and bind canonical chamber/schema identifiers to exact lowercase SHA-256 digests.
- Rules contain only `name`, `seekers`, and `artifacts`. Unknown `deny`, `effect`, `action`, operation, and other fields fail strict decoding.
- Rule names and selectors are unique. Both login and tag lists are explicit; at least one selector overall and one artifact pattern are required. Login/tag comparisons preserve exact case and bytes, and either a matching login or device tag independently satisfies identity selection.
- Chamber globs are anchored and case-sensitive. `*` consumes zero or more characters within one segment; a segment exactly `**` consumes zero or more complete segments. Partial `**`, `?`, character classes, braces, escaping, unsupported characters, empty/traversal segments, duplicate patterns, and patterns matching no locked artifact fail.
- Authorization is allow-only and default-deny. Rules authorize reveal only and never select guardians.

`DecodeDraft` retains strict syntax/known-field checks for caller-edited decree input while allowing the proclamation-authorized signer to replace managed generation and lock values. `tombstate.SignDraft` rejects the wrong proclamation, increments exactly once, regenerates exhaustive locks, validates the resulting policy, and emits an exact detached signature.

## Manifest, signature, lock, and transition verification

`internal/tombstate` owns the public trust state.

- Tomb manifests strictly validate version 1, lowercase UUIDv4 tomb IDs, fixed proclamation KDF/age/signature suites, canonical salt, native hybrid recipient, exact-width public keys, and re-derived fingerprint.
- Detached decree envelopes strictly bind version, tomb ID, externally pinned key fingerprint, SHA-256 of exact `tomb.yaml` bytes, exact decree bytes, and both Ed25519 and ML-DSA-65 components under purpose `sphinx decree`.
- Verification authenticates exact decree bytes before parsing or evaluating policy, then compares every exhaustive lock against exact committed Git blob bytes.
- `gitresource.Content` retains all three exact blobs for every contiguous rotation sequence rather than only checking filenames.
- Rotation transition and signature envelopes strictly bind sequence, tomb ID, exact transition payload digest, signer role/fingerprint, and distinct `/from` and `/to` purposes. Both signatures must verify with their declared public bundles.
- Chains start at sequence one, remain contiguous, link exact signing-bundle fingerprints, contain the externally pinned fingerprint, and end at the complete current manifest public bundle. Missing, reordered, disconnected, altered, or singly signed transitions fail.
- Initial enrollment derives commit/fingerprint/generation only from a self-consistent verified tomb and still requires caller trust approval for the returned fingerprint.

`AdvanceLock` verifies both current and candidate signed states, requires the configured generation to match the current tomb, rejects lower generations, and accepts equal generations only for byte-identical manifest, decree, signature, artifact/schema, and rotation state. It advances to the candidate's verified current proclamation fingerprint and UTC timestamp. `lockedresource.PrepareTrustedUpdates` combines this validation with the Phase 2 descendant-only candidate preparation; `InstallUpdates` remains the stale-checked all-or-nothing project-config replacement.

## Signed worktree mutations

The Phase 4 mutation interface now has a concrete authenticated implementation.

- `NewMutationBuilder` verifies the complete current signed tomb before retaining policy, checks the prompted proclamation signing identity against the manifest fingerprint, and refuses a tampered current policy.
- `MutationBuilder` discovers the complete virtual managed-path inventory, increments generation exactly once, regenerates every artifact/schema digest, preserves policy rules, and signs the exact decree against the unchanged manifest.
- Its validator reconstructs the virtual and installed tomb and performs complete signature, policy, transition, and exhaustive-lock verification.
- `ApplyMutation` couples the authenticated builder and validator so callers do not supply signed-state bytes or a weaker validator.
- All managed artifacts/schemas plus the manifest are read-only transaction dependencies. They are worktree-clean and TOCTOU guarded even when not replaced, preventing an unrelated dirty schema or artifact from being silently included in newly signed locks.
- Transaction guard matching now distinguishes exact post-images from explicit read-only dependencies. Dependencies are never journaled or replaced.
- Existing non-executable modes for artifacts, manifest, decree, and detached signature are preserved.

## Fresh current seeker and synchronous reveal

`internal/seeker.TailscaleResolver` performs one fresh `StatusWithoutPeers` LocalAPI request per call. It requires backend state `Running`, a node key, current tailnet, online self node, and at least one usable login or tag. Missing LocalAPI, stopped/logged-out/disconnected state, incomplete self state, and identity responses with neither fail closed. A tagged node without a user profile remains valid. There is no identity cache, command-output scraping, remote-peer `WhoIs`, offline mode, environment override, or grace period.

`internal/reveal.Coordinator` implements the synchronous reveal trust order:

1. Require the exact project-locked commit.
2. Verify pinned proclamation trust, transition chain, exact decree signature, exhaustive locks, and configured generation.
3. Verify the requested chamber's exact committed artifact digest.
4. Query the fresh current seeker and apply default-deny login-or-tag policy before loading any guardian record.
5. Strictly inspect repository-visible SOPS recipients and reject zero-guardian artifacts.
6. Resolve the schema from the same locked commit.
7. Visit only locally configured guardians in deterministic configuration order, discard recipients absent from the artifact, and stop at the first identity that unwraps the data key.
8. Require normal SOPS MAC verification and post-decryption schema conformance.

The coordinator returns an in-memory document only. Phase 6 owns terminal confirmation and exact stdout-only scalar/YAML/JSON rendering. Tests prove login-only, tag-only without profile, unavailable Tailscale, neither-identity rejection, default deny, stale-generation rejection before seeker lookup, no guardian loading before authorization, zero guardians, no recipient intersection, deterministic configured order, and successful MAC/schema-verified reveal.

## Complete proclamation rotation

`internal/proclamationrotation` performs one all-artifact transaction from already confirmed old/new proclamation derivations.

- It verifies the complete current tomb and old proclamation against the manifest before preparation.
- Every artifact is decrypted through the old proclamation, schema/MAC validated, has exactly its leading proclamation recipient replaced, preserves every guardian, receives an independent fresh data key, and fully re-encrypts every secret.
- It creates a new manifest, increments decree generation once, regenerates all locks, signs the decree with the new proclamation, appends the next fixed-width transition, signs it under both old/from and new/to purposes, and validates the candidate chain from the old externally trusted fingerprint.
- Artifacts, manifest, decree, signature, and all three transition files install in one exact-path transaction. Existing schemas and prior transitions are guarded read-only dependencies.
- Tests inject failure after every one of the seven install positions and prove exact restoration with no surviving transition. Successful rotation proves old-proclamation decryption failure, new-proclamation decryption success, mode preservation, generation advancement, and complete transition installation.

## Gates

Tests cover strict and malformed decrees, forbidden policy fields, login-or-tag semantics, glob edge cases, lock ordering/exhaustiveness/digest mismatch, signature tampering, wrong external pins, transition corruption, single- and multi-rotation traversal, missing/reordered transitions, old-generation replay, same-generation substitution, authenticated mutation construction, managed-field decree signing, live Tailscale states, guardian ordering/intersection, full reveal, complete rotation, transaction dependencies, and rollback injection.

`scripts/verify-phase5.sh` runs the Phase 5 package and race gates and scans the new production boundaries for external command execution, remote-peer identity lookup, and retired implementation terminology.
