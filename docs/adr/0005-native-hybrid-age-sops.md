# ADR 0005: Native hybrid age and SOPS

- **Status:** Accepted
- **Date:** 2026-08-21

## Context

The initial release requires post-quantum hybrid recipient wrapping without inventing a Sphinx-specific age or SOPS extension.

## Decision

Use `filippo.io/age v1.3.1` native `age.HybridRecipient` and `age.HybridIdentity`, and `github.com/getsops/sops/v3 v3.12.1` native age master keys, in process. The suite is `mlkem768x25519-v1`: ML-KEM-768 + X25519 through `hpke.MLKEM768X25519()`, HKDF-SHA-256, ChaCha20-Poly1305, and information label `age-encryption.org/mlkem768x25519`.

Accepted encodings are native `age1pq1…` recipients, `AGE-SECRET-KEY-PQ-1…` identities, and `mlkem768x25519` stanzas. Every recipient carries age label `postquantum`. Classical, plugin, mixed-suite, threshold, Shamir, KMS, PGP, SSH, and fallback encodings are rejected. Runtime code never executes age plugins or external age/SOPS commands.

Artifacts use SOPS v3.12.1 AES-256-GCM and MAC behavior with `encrypted_regex` exactly `^secrets$`. Each artifact has exactly one proclamation recipient and zero or more independent native hybrid guardian recipients.

## Pinned module checksums

- `filippo.io/age v1.3.1`: `h1:hbzdQOJkuaMEpRCLSN1/C5DX74RPcNCk6oqhKMXmZi0=`; module file `h1:EZorDTYUxt836i3zdori5IJX/v2Lj6kWFU0cfh6C0D4=`.
- `github.com/getsops/sops/v3 v3.12.1`: `h1:DZzLNJx6EH4SZvMjI1Y814WIcOQNUtOP3WgDsHNqQTU=`; module file `h1:Bs/geuL5shRiXi194TQaGFiLvzVpA6U8tTYRd84qdvM=`.

`go mod verify` is part of the executable gate.

## Evidence

`testdata/phase0/` contains a native hybrid identity and a SOPS 3.12.1 encrypted artifact. `scripts/verify-phase0.sh` builds exact age/SOPS versions, tests age interoperability in both directions, decrypts externally generated SOPS in process, and decrypts in-process SOPS with the external CLI.
