# ADR 0006: Proclamation credential bundle

- **Status:** Accepted
- **Date:** 2026-08-21

## Context

A proclamation must deterministically recover administrative encryption and signing identities without storing a random private bundle. Password-grade input would permit offline guessing against public recipients and keys.

## Decision

Sphinx generates ten independent words using unbiased rejection sampling from the exact EFF large wordlist dated 2016-07-18. The vendored bytes have SHA-256 `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e`. Words are joined by one ASCII space.

`argon2id-v1` is Argon2id v0x13 with a random 32-byte tomb salt, 262144 KiB memory, three iterations, four lanes, and 32-byte output. Three sibling 32-byte seeds are derived with HKDF-SHA-256 using a nil/empty HKDF salt and these exact ASCII info values:

- `sphinx/proclamation/age/mlkem768x25519`
- `sphinx/proclamation/sign/ed25519`
- `sphinx/proclamation/sign/ml-dsa-65`

The age seed is encoded directly as a native hybrid age private seed. Signing seeds use Ed25519 and ML-DSA-65 deterministic seed APIs. Proclamations are never accepted through argv, environment, files, or piped stdin and are never persisted.

## Consequences

Argon2id increases guess cost but public keys permit offline testing; source entropy is the primary defense. Generation, one-time display, confirmation, and all later prompts require a controlling terminal. Commands permit three attempts and have no persistent lockout.
