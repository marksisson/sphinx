# Phase 4 implementation record

Phase 4 establishes the strict initial-format SOPS artifact engine and the only fail-closed worktree installation path for artifact/schema mutations. Phase 5 supplies the concrete decree parser, exhaustive-lock encoder, and detached-signature verifier through the mandatory signed-state interface; Phase 6 binds these primitives to the final interactive commands.

## Initial-format artifact engine

`internal/artifact` now owns both the named-scalar plaintext model and its SOPS representation.

- Plaintext is exactly `format`, `schema`, `inscriptions`, and `secrets`. Both value branches accept only non-null string, integer, or boolean scalars; nested mappings, sequences, nulls, and undeclared schema fields fail.
- Every write resolves and validates the schema before encryption. Every successful decrypt verifies the SOPS MAC, decodes the strict plaintext artifact, requires the immutable schema reference to match the resolved definition, and validates all fields again.
- SOPS v3.12.1 encrypts only the complete `secrets` branch through `encrypted_regex: ^secrets$`. The engine uses AES-256-GCM value encryption and the normal SOPS MAC.
- Strict encrypted parsing rejects plaintext secrets, encrypted inscriptions, alternate selectors, suffix/comment modes, unknown metadata, unsupported versions, KMS/PGP/SSH/Vault providers, key groups, Shamir thresholds, malformed age armor, non-native stanzas, duplicate recipients, classical/plugin recipients, and inconsistent SOPS metadata.
- Exactly one recipient must equal the tomb proclamation recipient. Every other recipient is a unique native hybrid guardian recipient. Recipient metadata order does not change classification; Sphinx writes the proclamation first and preserves guardian order.
- SOPS master keys and identities enter only through `internal/hybridage`. Production code executes no external SOPS/age binary, discovers no plugin, reads no SOPS identity environment variable, and creates no identity file.

`Engine.Create` creates a proclamation-only artifact. `SetInscription`, full or selected-secret `Reseal`, `AddRecipient`, and `RemoveRecipient` require the proclamation identity, decrypt and validate first, preserve the schema reference, generate a fresh independent 32-byte SOPS data key, rewrap it for the complete resulting recipient set, and fully re-encrypt every secret. Adding a duplicate, removing an absent guardian, or removing the proclamation fails.

`DecryptWithIdentities` tries only eligible native hybrid identities in caller order and returns the recipient that succeeded, supporting deterministic guardian fallback in the Phase 5 coordinator. `Inspect` performs no decryption and returns only the readable schema, inscriptions, and recipient fingerprints with stable warning code `unverified_inscriptions` and a conspicuous SOPS-MAC warning.

## Signed mutation boundary

`internal/artifactmutation` prevents artifact-only writes.

- Callers provide only prepared artifact/schema changes.
- A mandatory `SignedStateBuilder` receives the complete virtual tomb view, regenerates exhaustive artifact/schema locks, and returns both proclamation-signed decree and detached-signature post-images.
- Callers cannot inject decree/signature bytes into the change set, and an incomplete pair fails before journaling.
- A mandatory complete-state validator checks the virtual post-state and the installed state.
- Scoped guardian add/remove prepares and validates every selected artifact first, consumes one distinct fresh data key per artifact, and submits all artifacts plus signed state as one transaction. Any preparation error writes nothing.

The Phase 4 tests use the frozen Phase 3 hybrid signature implementation to prove that changed artifact digests are covered by both signature components. The initial decree YAML grammar and production exhaustive lock builder remain deliberately owned by Phase 5 rather than introducing a temporary or compatibility decree format.

## Journaled transactions and recovery

`internal/transaction` installs exact post-images below an explicit caller-managed Git worktree.

- The interprocess lock uses `O_NOFOLLOW` plus `flock` in the resolved Git administrative directory.
- Guarded targets must exactly equal transaction targets. Worktree Git-operation, dirty-target, attribute, symlink, and TOCTOU checks run before journal creation.
- A mode-`0700` journal below `<git-dir>/sphinx/transactions/current` records a canonical sorted target list, exact pre/post existence, bytes, modes, SHA-256 digests, format version, and phase. It contains encrypted artifacts and readable tomb metadata only when reached through the artifact mutation boundary.
- Every post-image is prepared, synchronized, and validated as a complete virtual tomb before installation. Files use same-directory atomic replacement and directory synchronization; deletion is exact-path only.
- Ordinary errors after installation starts restore all exact pre-images. Rollback first requires every current path to match either its recorded pre-image or post-image and refuses to overwrite a third-party edit.
- A crash leaves the journal and blocks later mutation with recovery instructions. Authorized `RecoverRollback` restores only listed pre-images and validates the result. A committed journal is validated and cleaned without rollback.
- Corrupt journals fail closed and retain a separately synchronized target list for exact affected-path diagnostics.
- No transaction or recovery implementation invokes Git, resets a worktree, touches the index, creates a stash/commit, or modifies unrelated files.

## Fixtures and gates

`testdata/phase4/` freezes a strict schema/plaintext pair, proclamation-only artifact, independently re-encrypted multi-guardian artifact, checksums, and deterministic test-only hybrid identities. Production code never loads the private fixture identities.

Tests cover multi-scalar values, nested/null/sequence rejection, external Phase 0 artifact compatibility, proclamation-only creation, unauthenticated inspection warnings, exact-one-proclamation checks, independent guardian fallback, duplicate/threshold/unsupported metadata rejection, valid but wrong-proclamation artifacts, MAC tampering, full and selected reseal, inscription mutation, mandatory data-key replacement, full secret re-encryption on recipient changes, scoped rollback, digest mismatch, crash recovery, committed cleanup, symlinked locks, corrupt journals, and third-party-edit refusal.

`scripts/verify-phase4.sh` installs the pinned SOPS v3.12.1 test oracle in an isolated temporary `GOBIN`, decrypts both frozen artifacts through independent recipients, and confirms their complete scalar plaintext. External tools remain test oracles only.
