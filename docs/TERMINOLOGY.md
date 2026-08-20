# Sphinx Metaphor and Product Terminology

## Concept

**Sphinx** is the guardian of protected knowledge.

The product uses an Egyptian / mythological metaphor to make secrets-management concepts memorable while preserving a coherent mental model:

> A **Sphinx** guards **Tombs**. Tombs contain **Chambers**. Chambers hold **Relics**. Relics contain sealed secret material. **Seekers** and **Envoys** approach the Sphinx and answer a **Riddle** to prove their identity. **Decrees** determine whether they are granted **Passage**. Every decision is recorded in the **Chronicle**.

The metaphor should be strongest at the product and workflow layers. Low-level cryptographic primitives should generally retain conventional names where precision matters.

---

## Product Components

| Component | Canonical name | Meaning |
|---|---|---|
| Product and project | **Sphinx** | The complete secrets-management system |
| Command-line client | **Sphinx client** / `sphinx` | Sends Petitions and administers local Sphinx configuration |
| Server process | **Sphinx daemon** | Authenticates identities, evaluates Decrees, and reveals authorized Relics |
| Server host | **Temple** | The infrastructure on which a Sphinx daemon runs |
| Local directory or Git repository | **Tomb** | A versioned collection of sealed Relics guarded by Sphinx |

The executable is named `sphinx` and contains both client and daemon commands. **Seeker** and **Envoy** name authenticated identities, not software components: a Seeker may use the Sphinx client, while an Envoy may call the Sphinx API directly.

A Tomb may be a local directory or a Git repository hosted by GitHub or another Git service. Git transport and repository location do not change its resource model.

---

## Core Terminology

| Product concept | Term | Meaning |
|---|---|---|
| Secrets-management system / CLI / service | **Sphinx** | The guardian that controls access to protected knowledge |
| Secret store / vault / Git repository | **Tomb** | A versioned container for protected secrets |
| Sub-namespace / logical grouping | **Chamber** | A subdivision within a Tomb |
| Individual secret | **Relic** | A valuable protected item stored within a Chamber |
| Secret metadata | **Inscription** | Non-secret descriptive information attached to a Relic |
| Secret payload / value | **Essence** | The protected contents of a Relic |
| Authentication challenge | **Riddle** | A challenge posed by the Sphinx to verify identity |
| Human identity / caller | **Seeker** | A person requesting access |
| Service identity / workload | **Envoy** | A machine or service acting as an authenticated principal |
| Authorization policy | **Decree** | A rule describing who may perform which actions |
| Granted authorization | **Passage** | Permission to access or act on protected resources |
| Encryption / lock operation | **Seal** | Protect a Tomb or Relic from access |
| Decryption / unlock operation | **Unseal** | Make protected contents accessible |
| Audit log | **Chronicle** | The immutable historical record of actions and judgments |
| Audit event | **Entry** | A single record in the Chronicle |

---

## Resource Hierarchy

The primary resource hierarchy is:

```text
Sphinx
└── Tomb: production-secrets.git
    ├── Chamber: database
    │   ├── Relic: postgres-password
    │   └── Relic: replication-key
    └── Chamber: stripe
        └── Relic: api-key
```

A canonical path within that Tomb might therefore look like:

```text
database/postgres-password
```

where:

- `production-secrets.git` is the **Tomb**
- `database` is the **Chamber**
- `postgres-password` is the **Relic**

---

## Authentication Model: The Riddle

The **Riddle** represents the authentication challenge.

This mapping is intentionally close to the Sphinx myth: the Sphinx does not reveal protected knowledge merely because someone asks. The requester must first prove that they are entitled to proceed.

Conceptually:

```text
Seeker / Envoy
      |
      v
   Sphinx
      |
   Riddle
      |
 identity proof
      |
      v
  authenticated
```

A Riddle may correspond internally to one or more real authentication mechanisms, including:

- OIDC or workload identity
- signed challenges
- API credentials
- hardware-backed authentication
- MFA
- short-lived identity tokens
- cloud-provider identity assertions

The metaphor describes the interaction, not the cryptographic implementation.

### Design principle

**A Riddle is not a secret.**

A Riddle is the mechanism through which a caller proves identity. The protected secret remains a Relic inside a Tomb.

This distinction avoids conflating authentication material with the secret being protected.

---

## Authorization Model

After a Riddle has been answered successfully, the Sphinx evaluates applicable **Decrees**.

A Decree describes what an authenticated Seeker or Envoy may do.

Example conceptual policy:

```text
Decree:
  Envoy: payments-api
  Passage: production/stripe
  Privilege: reveal
```

This means that the `payments-api` Envoy may reveal Relics within the `production/stripe` Chamber.

The authorization flow is:

```text
Answer Riddle
     |
     v
Authenticated identity
     |
     v
Evaluate Decrees
     |
     +---- deny ----> No Passage
     |
     +---- allow ---> Passage granted
```

---

## Suggested Operations

The metaphor can extend naturally into CLI and API operations.

```bash
sphinx serve --tomb github:example/production-secrets --tomb-path secrets
sphinx relic reveal database/postgres-password

# Possible future administrative operations:
sphinx relic create database/postgres-password
sphinx tomb seal
sphinx chronicle read
```

Possible verbs:

| Operation | Preferred term |
|---|---|
| Create/store a secret | **Create** or **Entomb** |
| Retrieve a secret | **Reveal** |
| Encrypt / lock | **Seal** |
| Decrypt / unlock | **Unseal** |
| Grant access | **Grant Passage** |
| Remove access | **Revoke Passage** |
| Authenticate | **Answer Riddle** / **Solve Riddle** |
| Evaluate authorization | **Judgment** |
| Record audit event | **Chronicle Entry** |

For frequently used commands, clarity should take precedence over novelty. For example, `reveal` is preferable to `exhume`, even though the latter is more literal to the tomb metaphor.

---

## Extended Vocabulary

The following terms may be useful as the product evolves.

| Technical concept | Candidate term | Notes |
|---|---|---|
| Authorization decision | **Judgment** | The Sphinx decides whether Passage is permitted |
| Secret reference / pointer | **Glyph** | A symbolic reference to a protected object |
| Human-readable alias | **Cartouche** | A named identifier associated with an important object |
| Temporary credential | **Token** | Already fits both security and the metaphor |
| Temporary access | **Passage** | Naturally supports time-bounded access |
| Expiration / TTL | **Hourglass** | Best suited to UI language rather than core API fields |
| Recovery mechanism | **Scarab** | Protective symbolism; could represent recovery credentials |
| Backup store | **Catacomb** | A secondary or archival collection of protected Tombs |
| Cluster / collection of Tombs | **Necropolis** | Strong metaphor, potentially useful for infrastructure grouping |
| Region / deployment boundary | **Kingdom** | Could represent a geographic or administrative boundary |
| Environment | **Realm** | Example: development, staging, production |
| Resource path | **Passage** | May conflict with authorization; use carefully |
| Version history | **Strata** | Layers of historical state |
| Key generation / rotation era | **Dynasty** | Possible metaphor for cryptographic generations |

---

## Terminology Boundaries

Not every security term should be renamed.

Low-level cryptographic primitives should generally retain their conventional terminology, including:

- encryption key
- key-encryption key
- nonce
- ciphertext
- signature
- hash
- KMS
- HSM
- certificate
- public key
- private key

This preserves precision for security engineers, audits, incident response, and implementation documentation.

The metaphor is intended to improve the **product mental model**, not obscure the underlying security model.

---

## Product Language Principles

1. **The metaphor must clarify, not hide.** A new user should be able to infer roughly what a Tomb, Chamber, Relic, and Riddle mean.
2. **Use metaphor for nouns more aggressively than for verbs.** Resource names are encountered repeatedly and benefit from distinctiveness; operational verbs should remain easy to understand.
3. **Prefer mythologically coherent terms over generic Egyptian imagery.** Terms should map to a real conceptual role rather than existing only for flavor.
4. **Keep security-critical documentation bilingual where useful.** For example: “Riddle (authentication challenge)” or “Decree (authorization policy)” on first use.
5. **Do not rename cryptographic primitives where doing so would reduce precision.**
6. **The Sphinx is the active guardian.** Tombs store; the Sphinx authenticates, judges, grants Passage, and records the result.
7. **The Riddle proves identity; it does not contain the secret.**

---

## Canonical Product Narrative

> The **Sphinx** guards protected knowledge stored in **Tombs**. Each Tomb contains **Chambers**, and each Chamber holds **Relics** containing sealed secret material. A **Seeker** or **Envoy** approaching the Sphinx must answer a **Riddle** to prove its identity. The Sphinx then evaluates its **Decrees** and decides whether to grant **Passage**. Every authentication attempt, authorization decision, and secret operation is recorded in the **Chronicle**.

This narrative should serve as the anchor for naming new concepts as the product model expands.
