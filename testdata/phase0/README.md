# Phase 0 executable fixtures

These files are public test material. The hybrid private identity and plaintext are intentionally committed and must never be used outside tests.

- `eff_large_wordlist.txt`: exact EFF 2016-07-18 list, 7,776 entries.
- `hybrid-identity.txt` / `hybrid-recipient.txt`: native age v1.3.1 hybrid pair.
- `artifact.plain.yaml`: expected plaintext.
- `artifact.sops.yaml`: encrypted by SOPS v3.12.1 with `encrypted_regex=^secrets$` and the native hybrid recipient.
- `crypto-vectors.json`: fixed Argon2id, HKDF, Ed25519, ML-DSA-65, frame, signature, and fingerprint known-answer values.

Run the complete external interoperability gate from a Go-capable environment:

```console
scripts/verify-phase0.sh
```

The script installs exact oracle versions into a temporary directory, verifies module checksums, and runs `internal/phase0`. External commands are test oracles only and are prohibited from Sphinx runtime code.
