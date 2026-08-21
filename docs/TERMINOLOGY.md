# sphinx Metaphor and Product Terminology

## Concept

**sphinx** is the guardian of protected knowledge.

The product uses an Egyptian / mythological metaphor to make secrets-management concepts memorable while preserving a coherent mental model:

> A **sphinx** guards **tombs**. tombs contain **chambers**. chambers hold **relics**. relics contain sealed secret material. **seekers** and **envoys** approach the sphinx and answer a **riddle** to prove their identity. **decrees** determine whether they are granted **passage**. Every decision is recorded in the **chronicle**.

The metaphor should be strongest at the product and workflow layers. Low-level cryptographic primitives should generally retain conventional names where precision matters.

---

## Product Components

| Component | Canonical name | Meaning |
|---|---|---|
| Product and project | **sphinx** | The complete secrets-management system |
| Command-line client | **sphinx client** / `sphinx` | Sends petitions and administers local sphinx configuration |
| Server process | **sphinx daemon** | Authenticates identities, evaluates decrees, and reveals authorized relics |
| Server host | **temple** | The infrastructure on which a sphinx daemon runs |
| Local directory or Git repository | **tomb** | A versioned collection of sealed relics guarded by sphinx |

The executable is named `sphinx` and contains both client and daemon commands. **seeker** and **envoy** name authenticated identities, not software components: a seeker may use the sphinx client, while an envoy may call the sphinx API directly.

A tomb may be a local directory or a Git repository hosted by GitHub or another Git service. Git transport and repository location do not change its resource model.

---

## Core Terminology

| Product concept | Term | Meaning |
|---|---|---|
| Secrets-management system / CLI / service | **sphinx** | The guardian that controls access to protected knowledge |
| Secret store / vault / Git repository | **tomb** | A versioned container for protected secrets |
| Sub-namespace / logical grouping | **chamber** | A subdivision within a tomb |
| Individual secret | **relic** | A valuable protected item stored within a chamber |
| Secret metadata | **inscription** | Non-secret descriptive information attached to a relic |
| Secret payload / value | **essence** | The protected contents of a relic |
| Structured essence field | **facet** | One named value within a structured essence |
| Cryptographic key holder | **guardian** | The keeper of the Keychain-backed private key used by the sphinx daemon |
| Private key | **private key** | The guardian's safeguarded private key |
| Public key | **public key** | The guardian's public key used to seal relics |
| Operation request | **petition** | A request submitted to the sphinx |
| Generic or unauthenticated caller | **petitioner** | A person or workload submitting a petition |
| Authentication challenge | **riddle** | A challenge posed by the sphinx to verify identity |
| Authenticated human identity | **seeker** | A person whose identity has been established |
| Service identity / workload | **envoy** | A machine or service acting as an authenticated principal |
| Authorization policy | **decree** | A rule describing who may perform which actions |
| Granted authorization | **passage** | Permission to access or act on protected resources |
| Encryption / lock operation | **seal** | protect a tomb or relic from access |
| Decryption / unlock operation | **unseal** | Make protected contents accessible |
| Audit log | **chronicle** | The immutable historical record of actions and judgments |
| Audit event | **entry** | A single record in the chronicle |

---

## Resource Hierarchy

The primary resource hierarchy is:

```text
sphinx
└── tomb: production-secrets.git
    ├── chamber: database
    │   ├── relic: postgres-password
    │   └── relic: replication-key
    └── chamber: stripe
        └── relic: api-key
```

A canonical path within that tomb might therefore look like:

```text
database/postgres-password
```

where:

- `production-secrets.git` is the **tomb**
- `database` is the **chamber**
- `postgres-password` is the **relic**

---

## Authentication Model: The riddle

The **riddle** represents the authentication challenge.

A **petitioner** is the generic caller submitting a **petition**. After the riddle establishes identity, the petitioner is recognized as a human seeker or workload envoy.

This mapping is intentionally close to the sphinx myth: the sphinx does not reveal protected knowledge merely because someone asks. The requester must first prove that they are entitled to proceed.

Conceptually:

```text
  petitioner
      |
submits petition
      |
      v
   sphinx
      |
   riddle
      |
 identity proof
      |
      v
seeker / envoy
```

A riddle may correspond internally to one or more real authentication mechanisms, including:

- OIDC or workload identity
- signed challenges
- API credentials
- hardware-backed authentication
- MFA
- short-lived identity tokens
- cloud-provider identity assertions

The metaphor describes the interaction, not the cryptographic implementation.

### Design principle

**A riddle is not a secret.**

A riddle is the mechanism through which a caller proves identity. The protected secret remains a relic inside a tomb.

This distinction avoids conflating authentication material with the secret being protected.

---

## Authorization Model

After a riddle has been answered successfully, the sphinx evaluates applicable **decrees**.

A decree describes what an authenticated seeker or envoy may do.

Example conceptual policy:

```text
decree:
  envoy: payments-api
  passage: production/stripe
  Privilege: reveal
```

This means that the `payments-api` envoy may reveal relics within the `production/stripe` chamber.

The authorization flow is:

```text
Answer riddle
     |
     v
Authenticated identity
     |
     v
Evaluate decrees
     |
     +---- deny ----> No passage
     |
     +---- allow ---> passage granted
```

---

## Suggested Operations

The metaphor can extend naturally into CLI and API operations.

```bash
sphinx tomb update production
sphinx tomb protect production
sphinx relic reveal database/postgres-password

# guardian key operations:
sphinx guardian awaken
sphinx guardian behold

# Administrative operations:
sphinx relic entomb database/postgres-password
sphinx relic inspect database/postgres-password
sphinx relic inscribe database/postgres-password
sphinx relic reseal database/postgres-password
sphinx relic reveal database/postgres-password --facet password

# tomb lifecycle operations:
sphinx tomb status production

# Possible future operations:
sphinx tomb seal
sphinx chronicle read
```

Possible verbs:

| Operation | Preferred term |
|---|---|
| Initialize the guardian's private key | **awaken** |
| Print the guardian's public key | **behold** |
| Run the daemon for a tomb | **protect** |
| Create/store a secret | **entomb** |
| Update secret metadata | **inscribe** |
| Replace secret payload | **reseal** |
| Retrieve a secret | **reveal** |
| Select a structured value | **facet** |
| Encrypt / lock | **seal** |
| Decrypt / unlock | **unseal** |
| Grant access | **Grant passage** |
| Remove access | **Revoke passage** |
| Authenticate | **Answer riddle** / **Solve riddle** |
| Evaluate authorization | **judgment** |
| Record audit event | **chronicle entry** |

For frequently used commands, clarity should take precedence over novelty. For example, `reveal` is preferable to `exhume`, even though the latter is more literal to the tomb metaphor.

---

## Extended Vocabulary

The following terms may be useful as the product evolves.

| Technical concept | Candidate term | Notes |
|---|---|---|
| Authorization decision | **judgment** | The sphinx decides whether passage is permitted |
| Secret reference / pointer | **Glyph** | A symbolic reference to a protected object |
| Temporary credential | **Token** | Already fits both security and the metaphor |
| Temporary access | **passage** | Naturally supports time-bounded access |
| Expiration / TTL | **Hourglass** | Best suited to UI language rather than core API fields |
| Recovery mechanism | **Scarab** | Protective symbolism; could represent recovery credentials |
| Backup store | **catacomb** | A secondary or archival collection of protected tombs |
| Cluster / collection of tombs | **necropolis** | Strong metaphor, potentially useful for infrastructure grouping |
| Region / deployment boundary | **Kingdom** | Could represent a geographic or administrative boundary |
| Environment | **Realm** | Example: development, staging, production |
| Resource path | **passage** | May conflict with authorization; use carefully |
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

1. **The metaphor must clarify, not hide.** A new user should be able to infer roughly what a tomb, chamber, relic, and riddle mean.
2. **Use metaphor for nouns more aggressively than for verbs.** Resource names are encountered repeatedly and benefit from distinctiveness; operational verbs should remain easy to understand.
3. **Prefer mythologically coherent terms over generic Egyptian imagery.** Terms should map to a real conceptual role rather than existing only for flavor.
4. **Keep security-critical documentation bilingual where useful.** For example: “riddle (authentication challenge)” or “decree (authorization policy)” on first use.
5. **Do not rename cryptographic primitives where doing so would reduce precision.**
6. **The sphinx is the active guardian.** tombs store; the sphinx authenticates, judges, grants passage, and records the result.
7. **The riddle proves identity; it does not contain the secret.**

---

## Canonical Product Narrative

> The **sphinx** guards protected knowledge stored in **tombs**. Each tomb contains **chambers**, and each chamber holds **relics** containing sealed secret material. A **seeker** or **envoy** approaching the sphinx must answer a **riddle** to prove its identity. The sphinx then evaluates its **decrees** and decides whether to grant **passage**. Every authentication attempt, authorization decision, and secret operation is recorded in the **chronicle**.

This narrative should serve as the anchor for naming new concepts as the product model expands.
