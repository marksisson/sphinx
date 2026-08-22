# Cryptographic interoperability fixtures

These files are public test material. The hybrid private identity and plaintext are intentionally committed and must never be used outside tests. The canonical EFF wordlist is embedded from `internal/proclamation/eff_large_wordlist.txt` and verified directly by the interoperability tests.

- `hybrid-identity.txt` / `hybrid-recipient.txt`: native age v1.3.1 hybrid pair.
- `artifact.plain.yaml`: expected plaintext.
- `artifact.sops.yaml`: encrypted by SOPS v3.12.1 with `encrypted_regex=^secrets$` and the native hybrid recipient.
- `crypto-vectors.json`: fixed Argon2id, HKDF, Ed25519, ML-DSA-65, frame, signature, and fingerprint known-answer values.

Run the complete external interoperability gate from a Go-capable environment:

```console
scripts/verify.sh
```

The script installs exact oracle versions into a temporary directory, verifies module checksums, and runs `internal/interoperability`. External commands are test oracles only and are prohibited from Sphinx runtime code.
