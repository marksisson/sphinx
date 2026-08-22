# Architecture decision records

These accepted ADRs freeze the initial security and format decisions for the CLI architecture. [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md) remains the complete normative specification; an ADR records why an implementation boundary exists and the evidence required to change it.

1. [Local policy threat model](0001-local-policy-threat-model.md)
2. [Canonical tomb repository layout](0002-tomb-repository-layout.md)
3. [Tomb-reference grammar](0003-tomb-reference-grammar.md)
4. [Chamber paths and artifact resolution](0004-chamber-paths.md)
5. [Native hybrid age and SOPS](0005-native-hybrid-age-sops.md)
6. [Proclamation credential bundle](0006-proclamation-credential-bundle.md)
7. [Hybrid decree-signature suite](0007-hybrid-decree-signatures.md)
8. [Decree trust bootstrap and rotation](0008-decree-trust-bootstrap.md)

Changes to an accepted wire format, trust boundary, or pinned suite require a superseding ADR and the rotation/format-version process in [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md).
