# Canonical terminology

These terms are normative for package names, CLI help, formats, documentation, tests, and errors.

| Term | Meaning |
|---|---|
| **Sphinx** | The synchronous local CLI |
| **tomb** | A Git repository containing encrypted artifacts and canonical `.tomb/` metadata |
| **tomb reference** | A canonical repository locator using `github:`, `git+https://`, `git+ssh://`, or `path:` |
| **chamber** | An exact case-sensitive repository path containing `artifact.yaml` |
| **artifact** | One schema-conforming SOPS document |
| **secret** | An encrypted top-level scalar beneath an artifact’s `secrets` mapping |
| **inscription** | A readable top-level scalar beneath `inscriptions`, authenticated only after MAC verification |
| **schema** | A tomb-local `name/vN` scalar-field definition |
| **guardian** | A credential-provider-backed native hybrid age identity |
| **proclamation** | A generated ten-word administrative credential and its derived trust identity |
| **seeker** | The current live Tailscale login and/or device tag |
| **decree** | The hybrid-signed allow-only reveal policy and exhaustive artifact/schema locks |
| **project lock** | The consuming project’s exact commit, proclamation fingerprint, decree generation, timestamp, and guardian selection |
| **transition** | One append-only cross-signed proclamation change |
| **recipient** | A public age key authorized to wrap an artifact data key |
| **identity** | Private age material capable of unwrapping an artifact data key |
| **data key** | A fresh independent 32-byte key used by SOPS for one artifact mutation |

## Relationships

```text
project Git repository
└── .sphinx/config.yaml
    └── tomb lock
        ├── exact commit
        ├── proclamation fingerprint
        ├── decree generation
        └── ordered guardians

tomb Git repository
├── .tomb/tomb.yaml
│   └── proclamation public trust
├── .tomb/decree.yaml + signature
│   ├── seeker allow rules
│   └── exhaustive locks
├── .tomb/schemas/NAME/vN.yaml
└── CHAMBER/artifact.yaml
    ├── schema reference
    ├── encrypted secrets
    ├── readable inscriptions
    └── proclamation + guardian recipients
```

A tomb is the repository-wide trust and storage boundary. A chamber names one exact location in that tomb. An artifact is the encrypted document at that location. A schema defines its scalar fields. The proclamation controls administrative changes; guardians enable operational reveal; seekers are authorized by the decree.

## Command language

Commands use nouns and explicit operations:

```text
sphinx tomb add|update|status|list|remove|validate|recover
sphinx artifact create|set-inscription|reseal|delete|inspect|reveal|validate
sphinx guardian create|show|list|delete|add|remove
sphinx decree init|sign|validate|show
sphinx proclamation rotate
```

`seal` may describe encryption in prose. `reseal` is the command that replaces all or one secret while rotating the complete artifact data key. `reveal` is the only seeker-authorized plaintext operation. `inspect` is public and explicitly unauthenticated until MAC verification.

## Cryptographic vocabulary

Conventional low-level terms retain their standard meanings: recipient, identity, ciphertext, data key, KEM, MAC, SOPS metadata, Ed25519, ML-DSA-65, ML-KEM-768, X25519, Argon2id, and HKDF.

A guardian and a proclamation both derive native hybrid age identities, but they have different roles:

- the proclamation recipient is mandatory and first in every artifact;
- guardian recipients are optional, unique, and independent;
- the proclamation signs tomb state and authorizes mutation;
- guardians are selected by consuming projects for reveal.

## Capitalization and paths

Use lowercase for generic domain nouns in prose and CLI examples. Use **Sphinx** for the product name. Preserve chamber path case exactly. Schema names and references are lowercase; field names may preserve ASCII case under their field grammar.

`.tomb/` always means tomb-owned metadata. `.sphinx/` always means consuming-project configuration. They are never aliases for each other.
