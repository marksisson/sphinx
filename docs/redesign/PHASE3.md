# Phase 3 implementation record

Phase 3 establishes the only accepted asymmetric identity, signature, proclamation, and guardian-provider boundaries. Artifact encryption and complete SOPS metadata validation remain Phase 4; decree formats and signed trust-chain evaluation remain Phase 5.

## Native hybrid age and SOPS

- `internal/hybridage` accepts only age v1.3.1 native `age.HybridRecipient` and `age.HybridIdentity` values.
- Canonical recipients begin `age1pq1`; canonical identities begin `AGE-SECRET-KEY-PQ-1`. Classical, plugin, whitespace-altered, case-altered, malformed, and alternate encodings are rejected before reaching SOPS.
- Deterministic proclamation seeds are encoded directly as the native 32-byte hybrid private seed and parsed by age. Sphinx does not substitute a deterministic random reader or independently construct KEM components.
- Guardian generation calls `age.GenerateHybridIdentity` and therefore uses the native suite's OS-CSPRNG path.
- SOPS v3.12.1 master keys are constructed only after strict hybrid-recipient parsing. Parsed hybrid identities are injected in process through `ParsedIdentities`; no identity files, SOPS identity environment variables, key services, plugins, or external commands are used.
- Tests assert the `mlkem768x25519` stanza, `postquantum` label, native SOPS data-key round trip, seed-derived identity known answer, and rejection of classical/plugin/noncanonical values.

## Hybrid signatures

- `internal/hybridsign` implements only `ed25519+mldsa65-v1` using Go Ed25519 and CIRCL v1.6.1 ML-DSA-65.
- Both keys derive from separate exact-width seeds. ML-DSA signing is deterministic and uses an empty context.
- Signing and verification APIs construct the fixed version-1 frame internally and accept only the decree and two proclamation-rotation purposes.
- Tomb IDs must be canonical lowercase UUIDv4 values. Decrees require one raw 32-byte manifest digest; transition purposes forbid one.
- Public keys and signatures use exact-width unpadded base64url components. Verification requires valid Ed25519 and ML-DSA-65 components.
- Public-bundle fingerprints hash separately length-prefixed suite, Ed25519 public-key, and ML-DSA-65 public-key bytes.
- Known-answer tests reproduce the Phase 0 frame, public keys, fingerprint, and both deterministic signatures, then test wrong payloads, missing/wrong-width components, corrupt classical and post-quantum signatures, fingerprint mismatch, and purpose/framing confusion.

## Proclamations

- `internal/proclamation` embeds the exact 7,776-entry EFF large wordlist and verifies SHA-256 `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e` before use.
- Generation selects ten independent words with OS-CSPRNG-backed 16-bit rejection sampling and joins them with one ASCII space. Caller-chosen or non-list proclamation phrases cannot enter derivation.
- `argon2id-v1` is fixed at Argon2id 0x13, 262144 KiB, three iterations, four lanes, a 32-byte salt, and a 32-byte root. Salt encoding is canonical unpadded base64url.
- HKDF-SHA-256 uses nil salt and the three frozen age, Ed25519, and ML-DSA-65 labels. Root and seed buffers are cleared after expansion.
- The resulting private bundle contains independent native hybrid age and signing identities. Its public view contains only pinned suite identifiers, salt, recipient, signing public keys, and signing-bundle fingerprint.
- `/dev/tty` is the only production prompt/display path. Generated proclamations are shown once there and require exact re-entry. Existing proclamations permit at most three terminal attempts. Echo is disabled by `term.ReadPassword`; piped stdin, argv, files, and proclamation environment variables are not input paths.

## Guardian records and providers

- `internal/guardian` defines canonical version-1 guardian JSON with name, suite, private native hybrid identity, recipient, fingerprint, and canonical UTC creation time.
- JSON parsing rejects unknown fields, duplicates/alternate serialization through canonical byte comparison, trailing data, unsupported suites, malformed identities, and recipient/fingerprint metadata that cannot be re-derived exactly.
- Guardian fingerprints are `SHA256:` plus unpadded base64url SHA-256 of the exact ASCII hybrid recipient.
- `internal/guardianstore` has no filesystem store. Writable providers generate locally and use create-without-overwrite semantics; no update, sharing, import, export, or recipient-only operation exists.
- Apple records are generic-password items under service `dev.marksisson.sphinx.guardians`, account `guardian:<name>`, and label `Sphinx guardian “<name>”`.
- `apple-icloud-keychain` is synchronizable and `apple-login-keychain` is explicitly non-synchronizable. Both use `kSecAttrAccessibleWhenUnlocked`; exact reads/deletes include the synchronization attribute, while listing uses `kSecAttrSynchronizableAny` and trusts returned item attributes to identify the provider. There is no iCloud-to-login fallback.
- The `environment` provider reads only `SPHINX_GUARDIAN`, containing canonical unpadded-base64url encoding of the same canonical record bytes. It is read-only and validates the configured name. Project configuration rejects more than one environment guardian selection per process.
- macOS defaults to `apple-icloud-keychain`. Other builds have no default or writable provider and can consume only an explicitly selected environment record; they are not initial release targets.

Private record and derivation buffers are copied minimally and cleared where practical. The only production persistence of guardian private material is the selected credential provider.
