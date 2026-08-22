# Phase 4 artifact fixtures

These files freeze initial-format multi-secret and multi-inscription SOPS artifacts produced through the native in-process age v1.3.1 and SOPS v3.12.1 engine.

- `schema.yaml` and `plain.yaml` define the strict plaintext input.
- `proclamation-only.sops.yaml` has exactly one native hybrid proclamation recipient.
- `multi-guardian.sops.yaml` adds one independent native hybrid guardian recipient and uses a distinct SOPS data key with complete secret re-encryption.
- `test-identities.txt` contains deterministic hybrid private identities **for tests only**. It must never be loaded by production code or used outside tests.

SHA-256:

```text
612d4ab548aa9f7f66725df830c61396a50384b616a88ed3093fb082ad840a97  multi-guardian.sops.yaml
35e4018bd3d39521dd26da1428eccc2f8bce5639d8081e4721173ce59dec910f  plain.yaml
f90d0b09fd64c7184ab598f48daf6d07bfa736e1bc455dc36a66df272795b690  proclamation-only.sops.yaml
37d3059f6df8561c229b15e09749ca6b876f6907635c8d9c99f9a0991609abb4  schema.yaml
098fda7fce1e00f40a0e59f7a53d4be45c391427d1fcc31e701db3146aac2838  test-identities.txt
```
