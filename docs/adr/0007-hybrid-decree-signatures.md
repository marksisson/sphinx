# ADR 0007: Hybrid decree-signature suite

- **Status:** Accepted
- **Date:** 2026-08-21

## Context

Readable decrees and exhaustive locks require administrative authenticity independent of age encryption and resistant to compromise of either one classical or one post-quantum signature component.

## Decision

`ed25519+mldsa65-v1` uses Go Ed25519 and CIRCL v1.6.1 FIPS 204 ML-DSA-65. Ed25519 uses `ed25519.NewKeyFromSeed`; ML-DSA uses `mldsa65.NewKeyFromSeed` and deterministic `SignTo(..., nil, false, ...)`. Both sign and verify the same frame; acceptance requires both.

The frame is fixed ASCII `sphinx-signature-v1`, followed by purpose, lowercase UUID tomb ID, raw 32-byte manifest digest (zero-length only where inapplicable), and exact payload bytes. Each variable field has an unsigned 64-bit big-endian byte-length prefix. ML-DSA context is empty. Raw public keys and signatures use unpadded base64url and exact algorithm lengths.

The public-bundle fingerprint is `SHA256:` plus unpadded base64url SHA-256 of the separately length-prefixed ASCII suite ID, raw Ed25519 public key, and raw ML-DSA-65 public key.

## Pinned module checksum

`github.com/cloudflare/circl v1.6.1` is pinned as `h1:zqIqSPIndyBh1bjLVVDHMPpVKqp8Su/V+6MeDzzQBQ0=` with module file `h1:uddAzsPgqdMAYatqJ0lsjX1oECcQLIlRpzZh3pJrofs=`.

## Evidence

`testdata/interoperability/crypto-vectors.json` fixes Argon2id/HKDF outputs, signing public keys, frame bytes, fingerprint, and deterministic signatures. `TestProclamationAndSignatureKnownAnswerVector` regenerates and verifies every value.
