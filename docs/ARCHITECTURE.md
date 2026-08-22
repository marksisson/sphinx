# Sphinx CLI Architecture and Security Specification

**Status:** Normative for v0.1.0. The `darwin/arm64` artifact from source commit `6f60cbb6391025c5aec8bf262d2dcf85b1a5d6bf` has a hardened-runtime Developer ID signature and secure timestamp. Apple notarization submission `8d1637b5-2382-401f-8a5d-430fd936855e` was accepted, its ticket is stapled and validated on the disk image, Gatekeeper reports `Notarized Developer ID`, and checksums plus a CycloneDX SBOM are published under `artifacts/releases/v0.1.0/`.

## 1. Purpose

Sphinx is a **local command-line tool only**. It manages Git-backed tombs, schema-conforming SOPS artifacts, age identities, and Tailscale-based access policy without an HTTP server, daemon, listener, LaunchAgent, or client/server protocol.

This document specifies the implemented architecture and security boundaries. Normative words such as **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are intentional.

The initial supported platform is macOS on Apple Silicon (`darwin/arm64`) only. Initial implementation, packaging, CI, credential-provider behavior, and release acceptance target that architecture only. Linux and Windows are not initial release targets. The documented Linux provider restrictions define future behavior if Linux support is added; they do not require a Linux binary in the initial release.

## 2. Canonical terminology

[`TERMINOLOGY.md`](TERMINOLOGY.md) defines the normative product, format, command, and cryptographic vocabulary used by this specification.

## 3. Non-negotiable properties

1. Sphinx MUST run to completion as a CLI process. It MUST NOT listen on a socket or expose an HTTP API.
2. Every asymmetric age identity and recipient created or accepted by Sphinx MUST use the selected **hybrid classical + post-quantum suite**. Classical-only X25519 identities MUST be rejected.
3. Every artifact MUST wrap its SOPS data/session key for exactly one proclamation recipient and zero or more guardian recipients. All recipients are independent hybrid-PQ recipients; any one can unwrap the data key. Threshold groups and classical-only recipients are prohibited.
4. Artifact creation/deletion, any secret or inscription update, recipient change, schema-file change, decree change, and reseal MUST require a proclamation; artifact schema-reference mutation is unsupported after creation.
5. Guardians MAY reveal artifacts but MUST NOT be sufficient through the Sphinx CLI to create or modify them.
6. A newly written artifact MUST conform to its referenced schema before it is committed to disk.
7. A revealed artifact MUST pass tomb-reference validation, chamber-path validation, lock validation, SOPS MAC verification, decryption, and schema validation before any value is emitted.
8. Sphinx MUST obtain the current seeker through the local tailscaled LocalAPI and apply the tomb's decree with default-deny behavior.
9. A remote or mutable tomb reference MUST resolve through an explicit lock. Normal reveal and mutation operations MUST NOT silently advance a mutable `ref`.
10. Sensitive prompts MUST use a controlling terminal with echo disabled. Proclamations and decrypted secrets MUST NOT be accepted through command arguments or environment variables.
11. Encrypted and metadata writes MUST use private staging files, `fsync`, atomic replacement, and path/symlink escape checks. Decrypted plaintext MUST NOT be staged in a file.
12. Sphinx MUST NOT create a persistent local event or audit store.
13. Initial artifact authoring is interactive-only on macOS and MUST use the controlling terminal for proclamations and secret/inscription input.

## 4. Architecture

```text
sphinx CLI
  ├── command layer
  │   ├── tomb
  │   ├── artifact
  │   ├── guardian
  │   ├── proclamation
  │   └── decree
  ├── tomb-reference parser + lock resolver
  ├── chamber path resolver
  ├── Git materializer
  ├── Tailscale seeker resolver
  ├── decree parser/evaluator
  ├── schema loader/validator
  ├── proclamation prompt/derivation
  ├── hybrid-PQ age identity provider
  └── SOPS YAML engine
```

There is no privileged intermediary. Every command operates locally on a locked materialization or an explicitly selected writable Git worktree.

### CLI reveal coordinator

The in-process reveal coordinator performs one synchronous operation using four required inputs:

1. the current local Tailscale identity (**seeker**);
2. the configured and locked Git repository (**tomb**);
3. that tomb's authenticated authorization policy (**decree**); and
4. one or more locally configured hybrid-PQ age identities (**guardians**).

The coordinator authorizes the seeker against the requested artifact under the tomb decree, intersects configured guardians with the artifact's SOPS recipients, and attempts eligible guardians in deterministic configuration order. At least one configured guardian MUST successfully unwrap the SOPS data key. It then verifies the SOPS MAC and schema before returning all secrets by default or one selected secret when `--secret NAME` is supplied. The coordinator creates no listener, handler, request object, remote identity lookup, or long-running process.

### Important security boundary: advisory CLI policy

Sphinx uses an **advisory CLI policy**. Decrees govern conforming Sphinx operations, while the operating system and configured credential provider protect guardian identities. Sphinx does not claim that seeker authorization is a cryptographic key-release boundary.

A process or user that can obtain a guardian identity can invoke SOPS or age directly, decrypt artifacts without decree evaluation, and produce modified artifacts with valid SOPS MACs. The proclamation-signed artifact digest list ensures that conforming Sphinx commands reject such unauthorized modifications, but it cannot prevent direct decryption or use outside Sphinx.

Accordingly:

- Tailscale seeker resolution and decree evaluation are application-level controls.
- Credential-provider access control is the actual local boundary around guardian private keys.
- Proclamation signatures authenticate accepted decrees and exact artifact bytes.
- Tomb commit locks and proclamation-signed artifact/schema locks provide integrity for Sphinx workflows, not DRM against a local key holder.
- No external service, hardware gate, or cryptographic release mechanism is required by this design.

Documentation, help, errors, and security claims MUST preserve this distinction.

## 5. Resource model and repository layout

A tomb is a Git repository. The canonical layout is:

```text
.tomb/
  tomb.yaml                    # tomb ID and proclamation verification key
  decree.yaml                  # readable authorization policy
  decree.yaml.sig              # detached proclamation signature
  rotations/                   # append-only proclamation/suite trust transitions
    .keep                      # required zero-byte Git sentinel
  schemas/                     # canonical tomb-local schema hierarchy
    anthropic-api-key/v1.yaml
production/
  anthropic/                   # chamber: production/anthropic
    artifact.yaml              # exactly one artifact in this chamber
```

`.tomb/` is the canonical and reserved tomb metadata directory. A tomb MUST contain exactly `.tomb/tomb.yaml`, `.tomb/decree.yaml`, `.tomb/decree.yaml.sig`, `.tomb/rotations/.keep`, and the `.tomb/schemas/` hierarchy defined by this specification. Duplicate or alternate manifest, decree, signature, rotation-root, or schema-root locations MUST be rejected. `.sphinx/` is reserved for consuming-project configuration and is not tomb metadata.

A chamber is a slash-separated repository-relative path such as `production/anthropic`. Each chamber contains exactly one fixed-name `artifact.yaml`. Commands address an artifact with a tomb reference or configured tomb name plus a separate chamber; users do not encode chamber directories or artifact filenames in the tomb reference.

Each chamber segment MUST match `[A-Za-z0-9][A-Za-z0-9._-]*`. Chamber paths reject absolute paths, empty segments, `.`/`..`, percent/encoded separators, backslashes, any `.git` segment, the root `.tomb` metadata directory, and symlink traversal. Paths are exact ASCII and require no Unicode normalization. `artifact.yaml` MUST be a regular non-symlink file below the materialized tomb root.

## 6. Tomb references, chambers, and locks

### 6.1 Tomb references

A tomb reference identifies a Git repository and may include exactly one optional Git selector:

```text
github:acme/secrets
github:acme/secrets?ref=main
github:acme/secrets?rev=<full-commit-id>
git+https://git.example.com/acme/secrets.git?ref=release
git+ssh://git@git.example.com/acme/secrets.git?rev=<full-commit-id>
path:/absolute/path/to/git-worktree
path:.                         # relative to the current directory
```

Only `ref` and `rev` query parameters are supported. `ref` names a mutable branch or tag; `rev` names a full immutable commit ID. They are mutually exclusive. A tomb reference MUST NOT encode artifact files, chamber paths, or checkout directories. Generic HTTP resources, archives, embedded credentials, fragments, unknown/repeated query parameters, and non-Git local directories are rejected. A relative `path:` reference is resolved against the current directory, canonicalized without symlink traversal, and MUST resolve to the Git worktree root rather than an arbitrary subdirectory. A configured short name such as `production-secrets` may stand for a complete tomb reference.

`github:` and `git+https://` use anonymous verified smart HTTPS with system TLS roots, direct dialing, and redirects limited to initial advertisement requests; credential helpers, `.netrc`, embedded credentials, ambient proxies, plaintext HTTP, and dumb HTTP are unsupported. `git+ssh://` uses only `SSH_AUTH_SOCK`, standard user/system known-host files, and the explicit URL user/host/port (default user `git`). Sphinx does not load SSH routing or identity configuration and does not support passwords, identity files, host aliases, `ProxyCommand`, `ProxyJump`, or other command/proxy directives. Transport diagnostics omit URLs, users, socket paths, host keys, and upstream error text.

A reference without a selector tracks the repository's default branch. For reveal operations, `--tomb` accepts either a project-configured tomb name or a tomb reference that matches a project lock. An optional global alias is only an enrollment convenience; it does not make a tomb usable until `sphinx tomb add` writes a lock into the current project's `.sphinx/config.yaml`. Mutating tomb/artifact/decree commands instead require a local caller-managed worktree as specified in §6.4.

### 6.2 Chamber resolution

A chamber is supplied separately from the tomb:

```text
tomb:    github:acme/secrets
chamber: production/anthropic
file:    production/anthropic/artifact.yaml   # derived, never supplied
```

Sphinx validates the chamber and deterministically appends `artifact.yaml`. Decrees match canonical chamber paths, not Git URLs or arbitrary filenames.

### 6.3 Global aliases and project locks

Sphinx has two separate configuration scopes:

1. **Optional global configuration:** XDG user configuration containing convenient tomb aliases and references, but no project locks or project policy.
2. **Required project configuration for project operations:** `.sphinx/config.yaml` at the current Git worktree root, containing the project's locked tombs and all other project-specific Sphinx settings.

Example global configuration:

```yaml
version: 1
tombs:
  company-secrets:
    reference: github:acme/secrets?ref=main
```

The global file is user-managed. Sphinx has no CLI command that adds, removes, renames, or updates global aliases.

Example project configuration:

```yaml
version: 1
tombs:
  default:
    reference: github:acme/secrets?ref=main
    lock:
      commit: <full-resolved-commit-id>
      proclamation_fingerprint: <trusted-signing-key-fingerprint>
      decree_generation: <monotonic-unsigned-integer>
      locked_at: <UTC timestamp>
    guardians:
      - name: personal-guardian
        # provider omitted: apple-icloud-keychain on macOS
```

Sphinx discovers the project root with Git's worktree-root semantics (equivalent to `git rev-parse --show-toplevel`) and uses `<root>/.sphinx/config.yaml` regardless of the current subdirectory. It MUST reject bare repositories, run outside a Git worktree, symlinked `.sphinx` components, and roots that cannot be resolved safely. Nested worktrees use the nearest enclosing Git worktree reported by Git.

The project configuration is intended to be committed with the project so collaborators share exact tomb commits. It contains no private identities, proclamations, or decrypted secrets. Writes MUST use an inter-process lock, a temporary file in `.sphinx`, `fsync`, atomic rename, and parent-directory sync while preserving the repository's chosen non-executable file mode.

`sphinx tomb add [--name NAME] TARGET` accepts either an alias from global configuration or a direct tomb reference:

- For a global alias, Sphinx copies the canonical reference into project configuration and uses the same alias unless `--name` overrides it.
- For a direct reference, the default name is the repository basename with a trailing `.git` removed.
- If the selected name or canonical reference already exists in project configuration, Sphinx fails rather than overwriting or inventing a suffixed name.

Add resolves and validates the candidate tomb, verifies the decree signature for internal consistency, displays the initial proclamation fingerprint for explicit trust approval, and atomically writes the project lock. Global configuration is never modified.

The alias `default` is reserved by behavior, not prohibited as a project tomb name. If `--tomb` is omitted, Sphinx uses the project tomb named exactly `default`. If no such entry exists, the command fails even when only one project tomb is configured.

`sphinx tomb update` with no argument updates every mutable tomb lock in project configuration. `sphinx tomb update NAME` updates only that project alias. Each candidate is independently materialized and validated and requires confirmation before project configuration is replaced. Its commit MUST descend from the existing lock. Its proclamation fingerprint MUST either remain unchanged or be reachable from the pinned fingerprint through the candidate's valid contiguous cross-signed rotation chain. Its signed decree generation MUST be greater than the locked generation, or equal only when the manifest, decree, signature, artifact locks, and schema locks are byte-for-byte identical to the currently locked signed state; a lower or reused-but-different generation is a rollback and is rejected. The all-tombs operation MUST validate every candidate first and then either install all proposed commit/fingerprint locks atomically or install none. A `rev`-selected tomb is reported as immutable and unchanged.

### 6.4 Caller-managed writable tomb worktrees

Sphinx edits only a caller-managed local Git worktree. Artifact creation/reseal, guardian add/remove, decree mutation/signing, and other tomb content changes MUST target a `path:` tomb reference resolving to a non-bare writable worktree containing canonical `.tomb/` metadata. Remote references, immutable materialization caches, and consuming-project tomb locks are read-only and MUST be rejected as mutation targets.

Sphinx performs worktree discovery, status inspection, ref/remote validation, attribute evaluation, and prospective-object hashing in process through the pinned go-git engine. Runtime MUST NOT invoke a Git executable or use one as a fallback. Sphinx MUST NOT initialize repositories, create or switch branches, stage files, create commits, modify remotes, push, open pull requests, or update a consuming project's tomb lock as a side effect of tomb authoring.

Before mutation, Sphinx MUST reject an in-progress merge/rebase/cherry-pick, unmerged index entries, symlink escapes, and pre-existing unstaged/staged changes to files it will replace. The sole exception is `decree sign`, which intentionally accepts caller-edited `decree.yaml` and schema blobs as declared inputs while still requiring its generated signature/transaction outputs to be clean. Unrelated dirty files MAY remain. After mutation, Sphinx reports every changed path and recommends `sphinx tomb validate path:.`; the caller reviews, stages, commits, signs, pushes, and merges using normal Git tooling and repository policy.

A typical lifecycle is:

```console
cd /path/to/secrets-tomb
sphinx artifact reseal --tomb path:. production/anthropic
sphinx tomb validate path:.
git diff --stat
git add .tomb/decree.yaml .tomb/decree.yaml.sig production/anthropic/artifact.yaml
git commit -S -m "Reseal Anthropic credentials"
git push

cd /path/to/consuming-project
sphinx tomb update default
git add .sphinx/config.yaml
git commit -m "Update secrets tomb lock"
git push
```

The artifact/decree/signature mutation is proclamation-authorized in the tomb worktree. The consuming project's lock advances only later through an explicit `sphinx tomb update` after the tomb commit is available from its configured reference.

## 7. YAML formats

All Sphinx YAML formats are UTF-8 without BOM, use LF line endings, end with exactly one LF, and require strict decoding with known fields and deterministic validation. YAML anchors, aliases, custom tags, duplicate mapping keys at any depth, multiple documents, and merge keys are forbidden. Sphinx defines no maximum size for artifacts, schemas, decrees, individual secrets, or Git repositories and MUST NOT reject one solely because it exceeds an implementation-defined size threshold.

### 7.1 Schema

Initial schema format:

```yaml
version: 1
name: anthropic-api-key
description: Anthropic API credential
secrets:
  - name: api_key
    type: string
    required: true
    prompt: Anthropic API key
inscriptions:
  - name: environment
    type: enum
    values: [development, staging, production]
    required: true
    prompt: Deployment environment
```

The `secrets` and `inscriptions` containers are inherent to every artifact and are not chosen by a schema. A schema defines the allowed top-level field names, scalar types, required/optional status, prompts, and enum values inside those two containers. It cannot rename the containers, add arbitrary top-level data branches, or alter which branch SOPS encrypts.

Every schema MUST define at least one secret. `inscriptions` may be absent or empty in the schema. Field names match `[A-Za-z_][A-Za-z0-9_]*`, are unique across both groups, and artifact fields not declared by the schema are rejected. The schema top level permits only `version`, `name`, optional `description`, `secrets`, and optional `inscriptions`. Every field requires `name`, `type`, `required`, and `prompt`; only enum additionally requires `values`. Defaults, coercion, regex/range/length constraints, aliases, and implicit nulls are unsupported. Enum values are a non-empty unique list of strings. Secrets and inscriptions are only top-level named scalar values. Supported schema types are `string` (including multiline strings), `integer`, `boolean`, and string `enum`. Nested mappings, sequences/arrays, null values, and binary/tagged values are forbidden in both containers.

Schemas are always tomb-local below `.tomb/schemas/` at the same locked commit as the artifact. An artifact reference such as `anthropic-api-key/v1` resolves exactly to `.tomb/schemas/anthropic-api-key/v1.yaml`. External schema tombs, filesystem paths, and schema tomb references are unsupported. A schema name matches `[a-z][a-z0-9-]*`; its version is `v` followed by a positive decimal integer without leading zeroes. Changing schema meaning requires a new version.

### 7.2 Artifact

Initial plaintext shape before SOPS processing:

```yaml
format: 1
schema: anthropic-api-key/v1
inscriptions:
  environment: production
secrets:
  api_key: sk-ant-...
```

Every artifact inherently contains `format`, `schema`, `inscriptions`, and `secrets`. `inscriptions` and `secrets` are mappings keyed by schema-defined field names, and every mapped value is scalar. `secrets` MUST be present and non-empty; `inscriptions` MUST be present as a mapping but may be empty. Neither container may contain nested data.

SOPS MUST encrypt the complete `secrets` branch with `encrypted_regex` exactly `^secrets$` and leave `format`, `schema`, and `inscriptions` readable. The initial format uses SOPS v3.12.1 AES-256-GCM value encryption and its normal MAC, accepts `sops.version` exactly `3.12.1`, and rejects alternate encrypted/unencrypted selectors, suffix modes, KMS/PGP/SSH stores, key groups, and Shamir metadata. All readable values remain covered by the SOPS MAC. SOPS metadata is repository-visible and includes recipients.

Example encrypted shape:

```yaml
format: 1
schema: anthropic-api-key/v1
inscriptions:
  environment: production
secrets:
  api_key: ENC[AES256_GCM,...]
sops:
  age:
    - recipient: <proclamation hybrid-PQ recipient>
      enc: <wrapped SOPS data key>
    # Zero or more independent guardian recipients may follow.
    - recipient: <guardian hybrid-PQ recipient>
      enc: <wrapped SOPS data key>
  encrypted_regex: ^secrets$
  mac: ENC[AES256_GCM,...]
  version: <supported version>
```

`Secret` and `Inscription` remain the singular domain terms for one value; the persisted YAML container names are always plural.

### 7.3 Decree

Initial plaintext policy shape:

```yaml
version: 1
generation: 1
artifact_locks:
  - chamber: production/anthropic
    sha256: <64-lowercase-hex-digits>
  - chamber: production/openai
    sha256: <64-lowercase-hex-digits>
schema_locks:
  - schema: anthropic-api-key/v1
    sha256: <64-lowercase-hex-digits>
rules:
  - name: personal-admin
    seekers:
      logins: [user@example.com]
      tags: []
    artifacts:
      - "production/**"
```

The decree is readable plaintext and MUST NOT be SOPS encrypted. `generation` is an unsigned 64-bit integer initialized to one. Every proclamation-authorized change to tomb manifest, decree policy, artifact locks, or schema locks increments it by exactly one; unrelated Git-only changes leave it unchanged. Overflow is a hard format error. Its integrity and administrative provenance are provided by a detached proclamation signature. The tomb manifest stores the proclamation's public verification key and key fingerprint; `decree.yaml.sig` stores the signature metadata and signature bytes.

Sphinx MUST verify the signature before parsing or evaluating the decree. A caller edit invalidates the signature until `sphinx decree sign` securely prompts for the proclamation, validates policy plus exhaustive artifact/schema locks, signs it, verifies the result, and atomically replaces the decree and signature as one logical transaction. `decree init` creates the initial default-deny decree and tomb metadata in an existing Git worktree. Anyone may alter repository bytes, but only a proclamation holder can produce a decree that Sphinx accepts.

The signed decree contains exhaustive `artifact_locks` and `schema_locks` lists. Each artifact entry binds one canonical chamber path to the SHA-256 digest of the exact encrypted `CHAMBER/artifact.yaml` bytes as committed to Git. Each schema entry binds one canonical `name/vN` reference to the SHA-256 digest of the exact `.tomb/schemas/name/vN.yaml` Git blob. Digests are exactly 64 lowercase hexadecimal characters. Both lists are unique and sorted bytewise. Tomb validation MUST reject a missing or extra artifact/schema, an exact duplicate, an invalid order, or any digest mismatch. Discovery of artifacts excludes `.tomb/`; schema discovery accepts only the canonical schema hierarchy. Policy rules may grant only chambers present in `artifact_locks`.

Chamber paths are case-sensitive and case-preserving. Sphinx MUST NOT lowercase, case-fold, or reject a tomb solely because two chamber paths differ only by case. Validation and locked reads use exact paths from the committed Git tree. A caller-managed worktree on a case-insensitive filesystem may still be unable to represent or edit both paths; that is reported as a worktree/filesystem limitation rather than a tomb-format validation error.

This makes proclamation authorization cryptographically observable: a guardian can use its SOPS identity outside Sphinx to produce a different artifact with a valid SOPS MAC, but Sphinx rejects that artifact because its proclamation-signed digest no longer matches. SOPS MAC verification remains required for encrypted-document integrity; the signed digest additionally proves that the proclamation authorized the exact encrypted artifact accepted by Sphinx.

The signature MUST cover the exact decree bytes—including all artifact/schema locks—and bind the SHA-256 of the exact `tomb.yaml` bytes, signature format version, canonical tomb ID, and purpose (`sphinx decree`). Binding the manifest digest prevents unsigned KDF, recipient, or public-key metadata changes; binding the tomb ID prevents copying a valid decree into another tomb. Signed YAML is UTF-8 without BOM, uses LF line endings, and ends with exactly one LF. Verification occurs over exact bytes before YAML parsing.

Digest computation is over committed Git blob bytes, not platform-transformed checkout text. Locked validation reads blobs directly from the Git object database and never follows submodules, Git LFS pointers, or smudge filters. Tomb metadata, schemas, and `artifact.yaml` files MUST be regular blobs and MUST have byte-stable attributes: no `filter`, `working-tree-encoding`, or clean/smudge transformation, and no line-ending conversion. Authoring rejects managed paths whose effective attributes violate this rule and hashes the exact bytes that Git will commit. Sphinx uses SHA-256 regardless of the repository's Git object-hash algorithm.

Initial manifest and signature metadata:

```yaml
# .tomb/tomb.yaml
version: 1
tomb_id: <lowercase-UUIDv4>      # random and immutable
proclamation:
  kdf: argon2id-v1
  salt: <unpadded-base64url-32-byte-salt>
  age_suite: mlkem768x25519-v1
  age_recipient: <age1pq1...>
  signature_suite: ed25519+mldsa65-v1
  public_key:
    ed25519: <unpadded-base64url-public-key>
    ml_dsa_65: <unpadded-base64url-public-key>
  fingerprint: SHA256:<unpadded-base64url-digest>
```

```yaml
# .tomb/decree.yaml.sig
version: 1
tomb_id: <lowercase-UUIDv4>
key_fingerprint: SHA256:<unpadded-base64url-digest>
manifest_sha256: <64-lowercase-hex-digits>
signatures:
  ed25519: <unpadded-base64url-signature>
  ml_dsa_65: <unpadded-base64url-signature>
```

Rotation records use the same strict encodings:

```yaml
# .tomb/rotations/00000001.yaml
version: 1
sequence: 1
tomb_id: <lowercase-UUIDv4>
from:
  signature_suite: ed25519+mldsa65-v1
  public_key: {ed25519: <base64url>, ml_dsa_65: <base64url>}
  fingerprint: SHA256:<base64url>
to:
  kdf: argon2id-v1
  salt: <base64url>
  age_suite: mlkem768x25519-v1
  age_recipient: <age1pq1...>
  signature_suite: ed25519+mldsa65-v1
  public_key: {ed25519: <base64url>, ml_dsa_65: <base64url>}
  fingerprint: SHA256:<base64url>
```

Each `.from.sig`/`.to.sig` is a strict signature envelope containing `version`, `sequence`, `tomb_id`, `key_fingerprint`, `payload_sha256`, `purpose`, and separate base64url `ed25519`/`ml_dsa_65` signatures. The payload digest is lowercase hexadecimal and MUST match the exact transition bytes; purpose and signer fingerprint MUST match the file role.

**Trust bootstrap:** a public key stored only beside the decree is not sufficient because an attacker could replace both the decree and key. The proclamation verification-key fingerprint MUST also be pinned by the trusted tomb lock or local Sphinx configuration. Initial tomb enrollment is an explicit trust-on-first-use or out-of-band approval step. Normal reveal MUST require agreement among the locked fingerprint, tomb manifest key, signature key fingerprint, and verified signature.

`.tomb/rotations/` is an append-only trust-transition chain. It always contains a zero-byte regular `.keep` blob so an unrotated tomb has a committed canonical directory; `.keep` is never signed as a transition and any other non-sequence file is rejected. Each zero-padded sequence has fixed `NNNNNNNN.yaml`, `NNNNNNNN.from.sig`, and `NNNNNNNN.to.sig` paths. The exact transition bytes bind the format, sequence, tomb ID, previous proclamation fingerprint/public signing key/suite, and complete replacement public bundle: KDF profile and salt, age recipient, decree-signing suite/public key, and new fingerprint. The previous proclamation signature authorizes the replacement; the new proclamation countersignature proves possession. The previous signature uses purpose `sphinx proclamation rotation/from`; the new countersignature uses `sphinx proclamation rotation/to`, preventing role substitution.

Transition sequences MUST start at one, remain contiguous and immutable, and form an exact fingerprint chain ending at `.tomb/tomb.yaml`. Missing, reordered, duplicate, altered, singly signed, or disconnected transitions invalidate the candidate tomb. Retaining the complete chain allows a consuming project pinned to an older proclamation fingerprint to validate multiple rotations in one update.

Decrees authorize only artifact reveal. Rules are allow-only: there is no `deny`, `effect`, `actions`, or operation field. Chamber patterns are anchored to the whole chamber and matched case-sensitively: `*` matches zero or more characters within one segment, and a segment exactly equal to `**` matches zero or more complete segments. `?`, character classes, braces, backslashes, escaping, and partial-segment `**` are forbidden. Invalid patterns and patterns matching no locked chamber are rejected. A rule matches when its chamber pattern matches and either a configured Tailscale login or a configured device tag matches the current seeker (logical OR). Multiple matching allow rules remain allowed; no match is the default deny. Rule names match `[A-Za-z0-9][A-Za-z0-9._-]*` and are unique. Each rule has at least one login or tag and at least one artifact pattern; empty selector lists and duplicate selectors/patterns are rejected. Artifact patterns cannot grant access to an unlisted artifact.

## 8. Hybrid post-quantum cryptography

### 8.1 Required suite definition

The authoritative artifact-recipient implementation is the native standard hybrid implementation in `filippo.io/age` **v1.3.1**, compiled in-process with Go 1.26 or later. SOPS integration is pinned to `github.com/getsops/sops/v3` **v3.12.1**, whose age master-key implementation natively parses `age1pq1` recipients and `AGE-SECRET-KEY-PQ-1` identities. The module versions and checksums in `go.mod`/`go.sum` are part of the build input.

The normative age suite and wire format are exactly `age.HybridRecipient`/`age.HybridIdentity` from that version:

- hybrid KEM: `hpke.MLKEM768X25519()` (ML-KEM-768 + X25519/X-Wing construction);
- HPKE KDF and AEAD: HKDF-SHA-256 and ChaCha20-Poly1305;
- HPKE information/domain label: `age-encryption.org/mlkem768x25519`;
- recipient: Bech32 `age1pq1…` encoding of the native hybrid public key;
- identity: uppercase Bech32 `AGE-SECRET-KEY-PQ-1…` encoding of the 32-byte native hybrid private seed;
- age stanza: type `mlkem768x25519`, exactly one encoded encapsulation argument, and the standard wrapped file-key body;
- recipient label: `postquantum`, preventing unsafe mixing with non-PQ recipients;
- SOPS storage: the standard armored age-encrypted data key in each SOPS `age` master-key entry generated by SOPS v3.12.1.

The authoritative decree-signature implementation is Go 1.26 `crypto/ed25519` plus FIPS 204 ML-DSA-65 from `github.com/cloudflare/circl/sign/mldsa/mldsa65` **v1.6.3**. The proclamation derives one 32-byte seed for each component; Ed25519 uses `ed25519.NewKeyFromSeed`, and ML-DSA-65 uses `mldsa65.NewKeyFromSeed`. ML-DSA signing is deterministic (`randomized=false`). Public keys and signatures use their raw fixed-width encodings wrapped in unpadded base64url; malformed lengths are rejected. The detached signature always carries separate `ed25519` and `ml_dsa_65` values, and both MUST verify.

Both components sign the same unambiguous binary frame: ASCII magic `sphinx-signature-v1`, followed by the ASCII signature purpose, ASCII lowercase UUID tomb ID, raw 32-byte manifest SHA-256 (zero-length only where not applicable), and exact payload bytes, with every variable field prefixed by an unsigned 64-bit big-endian byte length. ML-DSA uses an empty FIPS 204 context because domain separation is already in the frame. The public-bundle fingerprint is `SHA256:` plus unpadded base64url of SHA-256 over the same length-prefixed suite ID and raw Ed25519/ML-DSA public keys. Decree and transition signatures use distinct purpose strings.

Sphinx links both libraries directly and MUST NOT discover, execute, or accept an age plugin or a custom master-key wire format. The `age-plugin-pq` program shipped from the same age v1.3.1 source may be used only as an external interoperability oracle in tests; it is not a Sphinx runtime dependency. Classical `age1…`, plugin `age1NAME1…`, `AGE-SECRET-KEY-1…`, and `AGE-PLUGIN-…` values are rejected.

The initial format has no algorithm negotiation or fallback. A future cryptographic suite requires a new format version rather than accepting alternate recipient/stanza encodings. The crypto ADR MUST copy these pinned facts, record dependency checksums and fixed known-answer artifacts, and demonstrate decrypt/re-encrypt interoperability with age v1.3.1 and SOPS v3.12.1; it does not need to invent a new hybrid construction.

Sphinx MUST reject a recipient if either the classical or PQ component is absent. Encryption MUST fail if either encapsulation cannot be produced. Decryption requires the intended native hybrid combination and never silently falls back to either component.

### 8.2 Guardians and credential providers

A guardian is one locally generated hybrid-PQ age SOPS identity. The configured secure credential provider is the sole authoritative store for both private identity material and guardian metadata. Sphinx MUST NOT maintain a separate filesystem guardian registry.

`sphinx guardian create NAME [--provider PROVIDER]` generates the X25519 + ML-KEM-768 identity with the OS CSPRNG and creates one versioned provider record. One record per guardian is required; separate `NAME-identity`, `NAME-recipient`, and `NAME-suite` records are prohibited because they can update or synchronize inconsistently.

For Apple providers, the generic-password item uses:

```text
service: dev.marksisson.sphinx.guardians
account: guardian:<name>
label:   Sphinx guardian “<name>”
data:    <versioned guardian record>
```

The protected record is strict version-1 JSON containing name, suite, private hybrid identity, public recipient, fingerprint, and creation metadata. Keychain stores those UTF-8 JSON bytes directly. `SPHINX_GUARDIAN` stores the same bytes as unpadded base64url. Unknown fields, duplicate keys, alternate encodings, and non-canonical derived metadata are rejected. On every read, Sphinx derives the recipient and fingerprint from the private identity and rejects the item if stored metadata does not match. A guardian fingerprint is `SHA256:` plus unpadded base64url SHA-256 of the exact ASCII `age1pq1…` recipient. Aliases are validated before being placed in `kSecAttrAccount`.

Apple provider variants are explicit:

- `apple-icloud-keychain` sets `kSecAttrSynchronizable = true` and is the default on macOS.
- `apple-login-keychain` creates a non-synchronizable item in the user's login/default Keychain domain.

Sphinx MUST NOT silently fall back from the iCloud provider to the login provider. If synchronizable storage is unavailable, creation fails with an actionable error. The iCloud provider uses `kSecAttrAccessibleWhenUnlocked`; device-only accessibility classes are not allowed.

A read-only `environment` provider supports CI systems such as GitHub Actions, including macOS CI in the initial release. Its record format is platform-independent for potential future use. It always reads exactly one fixed variable:

```text
SPHINX_GUARDIAN
```

Configuration MUST NOT select or interpolate arbitrary environment-variable names. The variable contains one versioned guardian record with name, suite, private hybrid identity, recipient, and fingerprint. Sphinx derives and verifies the recipient and fingerprint before use. The configured guardian name MUST match the record name.

The environment provider is read-only: get/existence and single-item listing are supported; create, update, and delete are not. Exactly one environment-backed guardian may be configured for a process. Sphinx rejects multiple environment guardian entries, a missing variable, malformed encoding, unsupported suite, name mismatch, and derived-metadata mismatch. It never logs the variable or includes it in errors and clears copied buffers where practical.

Linux is not an initial release target. If Linux support is added later, it has no persistent secure credential provider and no platform-default provider: Sphinx MUST NOT integrate with Secret Service, libsecret, KWallet, a filesystem key store, or another persistent Linux store. Such a build may consume only an explicitly configured read-only `environment` provider record; guardian create/update/delete return an unsupported-operation error. Omitting `provider` on Linux is a configuration error rather than a fallback to environment or disk.

The environment provider consumes only a pre-provisioned record. Sphinx does not generate, export, print, or convert such a record; the operator's secret-management/provisioning system is responsible for generating the pinned native identity and exact record format out of band. CI supplies the resulting value through its secret mechanism. For GitHub Actions:

```yaml
env:
  SPHINX_GUARDIAN: ${{ secrets.SPHINX_GUARDIAN }}
```

The environment provider deliberately exposes the guardian to the job environment and therefore has a weaker boundary than Keychain providers. Under the advisory CLI policy, any workflow step with equivalent process access may use the identity outside Sphinx. CI SHOULD use a dedicated guardian, protected environments/branches, pinned third-party actions, restricted decree chambers, and an ephemeral tagged Tailscale node.

`guardian list` queries generic-password items by the Sphinx service identifier and uses `kSecAttrSynchronizableAny` when listing across Apple providers. Exact get/delete operations include the expected synchronizable attribute so a local and synchronized item cannot be confused. Returned item attributes determine which provider owns the record.

Writable credential providers supply create-without-overwrite, get, list-by-service, existence, and delete operations. Guardian creation MUST use add semantics and refuse an existing provider/name pair; it MUST NOT silently call update. Read-only providers implement only their supported subset and return explicit unsupported-operation errors. Private bytes are cleared from process buffers where practical.

Sphinx does not provide guardian-recipient sharing, recipient import/export, recipient-only records, or commands accepting an arbitrary recipient string. `guardian show` displays provider, suite, and fingerprint but does not provide a share/export workflow. Public recipient material necessarily appears in SOPS metadata after a guardian is added to an artifact, but that is an artifact-format property rather than a guardian-distribution feature.

`guardian add` and `guardian remove` resolve `NAME` through explicit `--provider` or the macOS platform default, require one or more explicit chamber arguments or `--all`, and securely prompt for the proclamation. The resulting artifact set is the operation's scope.

Adding or removing a guardian generates a distinct fresh SOPS data key for every artifact in scope and fully re-encrypts every secret in each artifact; merely adding/removing a wrapped data-key stanza is forbidden. The operation then regenerates the exhaustive artifact/schema locks and signs the decree. The entire scoped artifact/decree/signature update is transactional: validation or write failure leaves every artifact unchanged. Add rejects an already-present recipient in any selected artifact; remove rejects a missing recipient in any selected artifact. Removal cannot revoke values previously revealed, so operational secret rotation may also be necessary.

Every artifact contains exactly one proclamation recipient and zero or more locally available guardian recipients. All recipients independently wrap the same SOPS data key (logical OR). SOPS key groups, Shamir splitting, quorum rules, and threshold behavior are prohibited. Guardian add/remove MUST preserve the one proclamation recipient and reject duplicate recipients. An artifact with zero guardians is valid for proclamation-authorized administration but cannot be revealed through the guardian-based reveal flow; validation MUST report that state clearly.

Deleting a guardian from its provider is distinct from removing it from an artifact. Because Sphinx has no global tomb registry, `sphinx guardian delete NAME [--provider PROVIDER]` cannot prove that no tomb still references it. It deletes the provider record only after confirmation and MUST always warn that artifacts may still contain its recipient. For `apple-icloud-keychain`, deletion may synchronize to other devices; iCloud Keychain is described as provider-managed synchronization/recovery, not guaranteed archival backup.

### 8.3 Proclamations

A proclamation is the high-entropy passphrase entered at the secure prompt. Sphinx deterministically derives the tomb's administrative keys from that passphrase; it does not store a randomly generated private credential bundle.

Standard age scrypt recipients are symmetric and have no public recipient key suitable for the required hybrid recipient or decree verification. Sphinx therefore uses a versioned deterministic construction:

```text
root = Argon2id(proclamation, tomb.proclamation.salt, pinned-parameters)
age_hybrid_seed     = HKDF-SHA-256(root, nil-salt, "sphinx/proclamation/age/mlkem768x25519", 32)
sign_classical_seed = HKDF-SHA-256(root, nil-salt, "sphinx/proclamation/sign/ed25519", 32)
sign_pq_seed        = HKDF-SHA-256(root, nil-salt, "sphinx/proclamation/sign/ml-dsa-65", 32)
```

The baseline key suites are:

- **Artifact age recipient:** X25519 + ML-KEM-768 hybrid; both components are required to recover a SOPS data key.
- **Decree signature:** Ed25519 + ML-DSA-65 hybrid; both signatures are generated and both MUST verify.

The signing keys are not age keys. They are sibling keys derived from the same Argon2id root with distinct domain-separation labels. An age identity is a KEM/decryption identity and MUST NOT be reused as a signing key. The tomb stores only the proclamation's hybrid age recipient, hybrid signing public key, KDF salt/parameter version, and fingerprints.

The proclamation's 32-byte `age_hybrid_seed` is encoded as the native `AGE-SECRET-KEY-PQ-1…` identity and parsed by age v1.3.1; that implementation expands the seed deterministically into the ML-KEM-768 and X25519 components. Sphinx MUST NOT substitute a deterministic random reader or derive the two KEM components independently. The two signing seeds use the pinned Ed25519 and CIRCL ML-DSA-65 deterministic seed APIs from §8.1.

The immutable `argon2id-v1` profile is:

```text
algorithm:   Argon2id version 0x13
salt:        32 random bytes per tomb
memory:      262144 KiB (256 MiB total)
time:        3 iterations
parallelism: 4 lanes
output:      32 bytes
```

These are fixed format parameters, not user-tunable settings. `.tomb/tomb.yaml` stores only `kdf: argon2id-v1` and the base64-encoded salt; arbitrary memory/time/parallelism values are rejected to prevent downgrade and resource-exhaustion values supplied by repository content. A future KDF profile requires proclamation rotation, a new profile identifier, and a cross-signed trust-transition record.

A new or rotated proclamation MUST be generated by Sphinx from the OS CSPRNG as ten independently selected words from EFF's `eff_large_wordlist.txt` dated 2016-07-18, whose exact vendored bytes have SHA-256 `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e`. Selection uses unbiased rejection sampling over all 7,776 entries. Words are joined by one ASCII space because some list entries contain hyphens. This provides approximately 129 bits of source entropy. Sphinx does not accept a caller-chosen password when initializing or rotating a proclamation, does not apply composition rules, and does not claim that an entropy estimator can make a memorable password safe. It displays the generated proclamation once on the controlling terminal and requires the user to re-enter it before committing any tomb change. The user is responsible for storing it in an appropriate password manager or equivalent protected system.

Because the public recipient and verification keys allow offline testing, Argon2id only increases guess cost; the generated entropy is the primary defense. Each command permits at most three proclamation prompt attempts and then exits. There is no persistent retry counter or artificial rate limiter because an attacker can test guesses offline without invoking Sphinx.

The proclamation MUST never be stored by Sphinx, logged, placed in argv/environment, written to stdout, or read from piped stdin. Generation and prompts use the controlling terminal. Derived material is cleared where practical and is never cached across commands.

### 8.4 Proclamation and suite rotation

`proclamation rotate` is an all-artifact administrative operation in a caller-managed worktree. It requires the current proclamation, generates and confirms a new ten-word proclamation, derives its new public bundle with a fresh 32-byte salt, and prepares a cross-signed transition record. It decrypts and validates every committed artifact, preserves each artifact's guardian set, replaces the one proclamation recipient, generates a fresh independent SOPS data key per artifact, and fully re-encrypts all secrets. It then regenerates all artifact/schema locks, signs the decree with the new proclamation, and replaces `tomb.yaml`.

The artifacts, decree, decree signature, tomb manifest, and three transition files are one journaled transaction. Any validation/write failure restores the exact old tomb. The old proclamation remains valid for rollback until the command reports success; Sphinx never deletes or overwrites a stored credential because proclamations are not stored. After success, the caller reviews, commits, and pushes normally.

A consumer remains on its old locked commit and proclamation fingerprint until `sphinx tomb update`. Update requires the candidate commit to descend from the currently locked commit, verifies the transition chain from the pinned fingerprint to the candidate manifest, verifies the candidate decree and every artifact under the new bundle, and only then atomically advances commit, proclamation fingerprint, and decree generation. Thus existing locks continue revealing the old committed state while updated locks move to the complete new state; no lock observes a partially rotated tomb.

The initial release does not implement generic hybrid-suite rotation or algorithm negotiation. A future suite change requires an ADR, a new format/suite identifier, and a bridge release that can read the old suite only for explicit rotation while writing and validating the new suite. Before installation, that bridge must stage replacement proclamation and guardian identities, cross-sign the transition with old and new decree-signing suites, and re-encrypt every artifact under only new-suite recipients in one transaction. Normal reveal never accepts a mixed-suite artifact. If any configured guardian lacks a new-suite identity, suite rotation fails before writing. Old-suite support may be removed only after the transition release and recovery window; Sphinx MUST NOT attempt an ad hoc or partial suite upgrade.

### 8.5 Age and SOPS responsibilities

Age remains required as the SOPS data-key recipient mechanism; it is not used for decree signing.

```text
artifact values ──encrypted by──> SOPS data key
SOPS data key   ──wrapped by────> hybrid-PQ age recipients
                                    ├── proclamation age recipient
                                    └── guardian age recipient(s)
decree bytes    ──signed by─────> proclamation Ed25519 + ML-DSA-65 keys
```

SOPS performs authenticated value encryption and MAC generation. Native age v1.3.1 wraps only the SOPS data/session key for the proclamation and guardians. The separate signing keys authenticate the readable decree. Sphinx MUST NOT use age as a signature primitive or SOPS-encrypt the decree.

Sphinx uses SOPS v3.12.1 and age v1.3.1 in-process. Guardian and proclamation identities are injected as parsed `age.HybridIdentity` values; they are never supplied through SOPS environment variables, identity files, key services, commands, or plugin discovery. No age plugin or custom SOPS master-key adapter is permitted at runtime.

For every artifact operation Sphinx MUST validate:

- supported artifact and SOPS versions;
- exactly the allowed encryption selector;
- no plaintext under `secrets` and no encrypted values outside policy unless explicitly supported;
- exactly one age recipient matches the tomb proclamation recipient and every remaining entry is a unique native hybrid-PQ recipient treated as a proclamation-approved guardian recipient by the signed artifact lock; local guardian availability is not required for structural validation;
- no unsupported KMS/PGP/SSH recipients, threshold key groups, Shamir configuration, or duplicate recipients;
- successful MAC verification;
- schema conformance after decryption.

## 9. Seeker identity and authorization flow

Sphinx obtains the **current local seeker**, not the identity of a remote HTTP peer. The resolver uses Tailscale LocalAPI rather than scraping human-readable command output. A seeker is identified by either a non-empty Tailscale login or at least one Tailscale device tag. Login and tags are optional individually but cannot both be absent. Decree logins compare exactly to the canonical LocalAPI login string; decree tags and LocalAPI tags compare exactly including the `tag:` prefix. Identity selectors allow no globbing, case folding, aliases, or whitespace normalization, and duplicates are rejected. Node ID/name may be retained as diagnostic metadata but are not decree identity selectors.

Reveal flow:

1. Parse the tomb reference—including its optional `ref` or `rev`—or configured tomb name, and validate the separate chamber path.
2. Require the tomb's approved lock and derive `CHAMBER/artifact.yaml`.
3. Fetch/materialize exactly the locked Git revision into the immutable object cache and validate Git tree entry types and paths. Locked reads use exact object-database blobs rather than a filesystem checkout, preserving case-colliding paths on macOS.
4. Load the tomb manifest, its one plaintext decree, and detached signature.
5. Require the proclamation verification-key fingerprint to match the trusted tomb lock/configuration pin, then verify the domain-separated decree signature before parsing the policy.
6. Require the chamber to appear exactly once in `artifact_locks` and verify its SHA-256 digest against the committed `CHAMBER/artifact.yaml` blob before inspecting SOPS metadata.
7. Query the local tailscaled LocalAPI for the current seeker and require an authenticated, connected tailnet state. Accept a login-identified seeker, a tag-identified seeker, or both; fail closed before loading any guardian identity if tailscaled is unavailable, stopped, logged out, disconnected, or returns neither a login nor any tags.
8. Evaluate the decree's allow-only reveal rules for the canonical chamber path. Login and device-tag matches are OR conditions; no matching rule is the default deny.
9. Read the tomb's ordered guardian names from local Sphinx configuration.
10. Intersect those configured guardians with the hybrid-PQ recipients in the artifact's SOPS metadata.
11. Load eligible guardian identities from their protected stores in deterministic configuration order until one successfully unwraps the SOPS data key. Fail closed if none can.
12. Decrypt and verify the artifact's SOPS MAC.
13. Resolve the artifact's schema reference at the same locked tomb revision and validate the decrypted document.
14. Emit all secrets by default, or only the named secret when `--secret NAME` was supplied.
15. Clear sensitive buffers where practical and return a meaningful exit status.

The decree authorizes the seeker to reveal the artifact; it does not grant cryptographic capability or select a guardian. A guardian must be both locally configured for the tomb and present in the artifact's recipient metadata. Seeker authorization and guardian decryption must independently succeed.

There is no offline reveal behavior. Every reveal MUST query tailscaled at execution time and fail closed. Sphinx MUST NOT cache seeker identity for later use or provide an offline flag, stale-identity grace period, environment override, or decree-bypass option. Proclamation-authorized administrative commands are not reveal operations and do not substitute for seeker authorization.

## 10. CLI contract

The final command structure is:

```text
sphinx tomb add [--name NAME] TARGET
sphinx tomb update [NAME]
sphinx tomb status [NAME]
sphinx tomb list
sphinx tomb remove NAME
sphinx tomb validate [NAME|path:WORKTREE]
sphinx tomb recover path:WORKTREE --rollback

sphinx artifact create --tomb path:WORKTREE --schema SCHEMA CHAMBER
sphinx artifact set-inscription --tomb path:WORKTREE --inscription NAME CHAMBER
sphinx artifact reseal --tomb path:WORKTREE [--secret NAME] CHAMBER
sphinx artifact delete --tomb path:WORKTREE CHAMBER
sphinx artifact inspect --tomb TOMB CHAMBER
sphinx artifact reveal --tomb TOMB [--secret NAME] CHAMBER
sphinx artifact validate --tomb TOMB CHAMBER

sphinx guardian create NAME [--provider PROVIDER]
sphinx guardian show NAME [--provider PROVIDER]
sphinx guardian list [--provider PROVIDER]
sphinx guardian delete NAME [--provider PROVIDER]
sphinx guardian add --tomb path:WORKTREE [--provider PROVIDER] NAME (CHAMBER... | --all)
sphinx guardian remove --tomb path:WORKTREE [--provider PROVIDER] NAME (CHAMBER... | --all)

sphinx decree init --tomb path:WORKTREE
sphinx decree sign --tomb path:WORKTREE
sphinx decree validate --tomb TOMB
sphinx decree show --tomb TOMB [--unverified]

sphinx proclamation rotate --tomb path:WORKTREE

sphinx completion SHELL
```

Rules:

- Read operations accept a project-configured alias/name or a tomb reference that canonically matches a project lock. Mutating artifact/guardian/decree/proclamation operations accept only an explicit local `path:` worktree. Omitting `--tomb` is available only to project-locked read operations.
- Omitting `--tomb` selects the project tomb named exactly `default`; there is no implicit single-tomb fallback.
- `tomb add` accepts a global alias or direct reference, validates and locks the tomb, and writes only `.sphinx/config.yaml`. A direct reference defaults to the repository basename when that name is unused.
- `tomb update` updates all mutable project tombs; `tomb update NAME` updates one. The update operation never changes global configuration.
- `tomb remove NAME` removes only that project lock/configuration entry after confirmation; it never edits global aliases, the remote repository, or the caller's tomb worktree. Cache entries are disposable implementation data, not tomb enrollment state.
- `artifact create` refuses overwrite, creates a proclamation-only artifact with zero guardians, and prompts for required fields while allowing optional fields to be skipped. It warns that reveal is unavailable until a guardian is added.
- `artifact set-inscription` prompts for one schema-declared inscription, decrypts the artifact administratively, preserves all other values/recipients, and fully re-encrypts under a fresh SOPS data key.
- `artifact reseal` is the general secret update operation. With no `--secret`, it prompts for and replaces every secret. With exactly one `--secret NAME`, it replaces only that named secret and preserves the other plaintext values. Every successful reseal generates a fresh SOPS data key and rewraps it for the unchanged recipient set, including when only one secret changes. Every mutation requires proclamation authorization.
- `artifact delete` requires confirmation and the proclamation, removes exactly one artifact, removes its lock, and re-signs the decree. Artifact schema references are immutable after creation in the initial release; changing schema version requires deletion/recreation.
- Every artifact creation, reseal, inscription change, guardian add/remove, or deletion MUST recompute affected artifact digests, regenerate the exhaustive artifact/schema lock lists, and sign the resulting decree with the same prompted proclamation. An artifact-only write is invalid.
- Multi-file mutation installs artifact(s), decree, and detached signature as one logical fail-closed transaction using the rollback protocol in §10.1. A failed command restores every affected path to its exact pre-operation state; a crash leaves a recoverable journal and blocks further mutation.
- `artifact inspect` MUST never print decrypted secrets. Without proclamation, guardian, seeker authorization, or SOPS decryption, it displays the readable schema reference, inscriptions, and recipient fingerprints together with a conspicuous warning that the values have not been verified through the SOPS MAC and MUST NOT be trusted as authenticated artifact content.
- `artifact reveal --tomb github:acme/secrets --secret api_key production/anthropic` resolves only `production/anthropic/artifact.yaml` and emits only `api_key` after the complete reveal validation flow.
- `artifact reveal` emits all secrets by default. In human mode, all-secret output is one UTF-8 YAML document containing only a top-level `secrets` mapping, with schema order preserved and no SOPS metadata. `--secret NAME` emits only the selected scalar: exact UTF-8 bytes for string/enum, canonical base-10 for integer, or lowercase `true`/`false` for boolean, with no added newline. JSON mode follows §10.2.
- `guardian create/show/list/delete` operate directly on credential providers; mutating commands fail for read-only providers such as `environment`. No filesystem registry or recipient share/import/export commands exist.
- `guardian add/remove` accept only guardian names resolvable through explicit `--provider` or the macOS default, MUST require a proclamation, and require one or more chambers or `--all`. Each operation fully re-encrypts every artifact in scope under a distinct fresh data key and commits all artifact/decree/signature changes atomically.
- `decree init` is the only tomb-metadata initializer. It operates in an existing caller-created Git root, creates `tomb.yaml`, the zero-byte `rotations/.keep` sentinel, a default-deny decree, and its signature, requires at least one valid schema and no existing artifacts. It generates the initial proclamation; it does not initialize Git or create a general repository scaffold.
- Decrees and schemas are edited directly by the caller as readable worktree files; Sphinx never launches an editor. `decree sign` requires the proclamation, validates the edited decree/schemas, regenerates exhaustive artifact/schema locks, and atomically installs the decree and detached signature. Generation and raw lock fields are Sphinx-managed rather than editor-authored.
- `decree show` displays the readable policy only after signature verification, unless `--unverified` requests unverified bytes with a prominent warning.
- `artifact validate` on a locked tomb follows the full authorized reveal/decrypt/MAC/schema flow but emits no secrets. `tomb validate NAME` performs public lock/manifest/decree/schema/artifact structural checks; `tomb validate path:WORKTREE` additionally prompts for the proclamation and fully decrypts/validates every artifact.
- `proclamation rotate` requires the current proclamation, generates and confirms a new proclamation, re-encrypts every artifact, replaces the tomb public bundle, signs the new decree, appends a cross-signed transition record, and commits the complete worktree mutation through the journaled transaction protocol.
- Stdout is the only decrypted-output channel in the initial interface; diagnostics and warnings go only to stderr. Sphinx provides no clipboard integration, named/arbitrary file-descriptor output, plaintext temporary/output files, or `exec` environment/stdin mode. Callers may explicitly pipe or redirect stdout using normal shell facilities and thereby assume the resulting leak/lifecycle risk.
- If decrypted stdout is a terminal, Sphinx emits a conspicuous stderr warning and requires controlling-terminal confirmation before emitting any secret. Piped stdout requires no extra confirmation. Secret values MUST NOT appear in diagnostics, errors, logs, terminal titles, or progress output.
- Artifact/decree/guardian/proclamation authoring requires a controlling terminal. Initial authoring rejects piped stdin, absent TTYs, command-line secret values, secret/proclamation environment variables, input files, and caller-supplied file descriptors. Reveal output may still be piped by the caller.
- Sphinx emits ordinary ephemeral diagnostics to stderr but creates no persistent event files, database, history, command, or configuration.

Sphinx only edits and validates caller-managed worktrees. Git initialization, branches, staging, commits, commit/tag signing, pushes, pull requests, merges, resets, and restores remain entirely caller-managed.

### 10.1 Multi-file rollback and crash recovery

Sphinx MUST NOT use `git reset`, `git reset --hard`, a stash, the index, or a temporary commit to implement rollback. Those mechanisms can alter HEAD, staged state, or unrelated caller changes and violate the caller-managed-worktree boundary.

Before changing any file, Sphinx acquires the tomb mutation lock, verifies that every target path is clean, and creates a mode-`0700` transaction directory below the worktree's Git administrative directory. The journal contains:

- the exact target path list;
- each path's pre-operation existence, bytes, mode, and SHA-256;
- every fully prepared post-operation file and SHA-256;
- transaction phase and format version.

The journal contains encrypted artifacts and readable tomb metadata only, never plaintext secrets or the proclamation. Sphinx writes, `fsync`s, and validates all post-images as a virtual complete tomb before installing any of them. It then installs each path with same-directory temporary files, atomic rename, and directory synchronization. After complete installed-state validation, it marks the transaction committed and synchronizes that marker before deleting the journal.

An ordinary error before the committed marker causes immediate rollback from the journal. Rollback restores only the listed paths and never touches unrelated files, HEAD, or the Git index. Before restoring a path, Sphinx requires its current digest to equal either the recorded pre-image or post-image; an unexpected third-party edit causes recovery to stop rather than overwrite caller data.

If the process crashes without a committed marker, all subsequent tomb mutations fail with recovery instructions. `sphinx tomb recover path:WORKTREE --rollback` prompts for the proclamation that authorized the operation (the pre-operation proclamation for a rotation, or the newly generated proclamation for initialization), validates the journal and applicable signed state, restores the complete pre-operation state, validates it, and removes the journal. A committed journal is completed/cleaned rather than rolled back. The initial interface does not offer roll-forward for an uncommitted transaction: if the initiating command did not report success, rollback is the deterministic outcome.

If the journal is corrupt or unavailable, Sphinx fails closed and prints the exact affected paths. Because target paths were required to be clean before mutation, the caller may inspect them and manually run path-scoped `git restore --source=HEAD --worktree -- <paths>` plus remove any newly created paths. Sphinx MUST never recommend a repository-wide reset or execute recovery Git commands itself.

### 10.2 Stable exit codes and JSON

Sphinx uses the macOS/BSD `sysexits` categories as its stable process-exit contract:

| Code | Symbol | Meaning |
|---:|---|---|
| 0 | `EX_OK` | Command completed successfully |
| 64 | `EX_USAGE` | Invalid command, flag, argument, or unsupported input mode |
| 65 | `EX_DATAERR` | Invalid schema/artifact/decree/YAML, signature/MAC/digest failure, or other rejected repository data |
| 66 | `EX_NOINPUT` | Required tomb, chamber, artifact, schema, config, or path does not exist |
| 69 | `EX_UNAVAILABLE` | Required external facility such as tailscaled, Git transport, Keychain, or configured provider is unavailable |
| 70 | `EX_SOFTWARE` | Internal invariant violation or unexpected implementation failure |
| 73 | `EX_CANTCREAT` | Required local file or transaction journal cannot be created/replaced |
| 74 | `EX_IOERR` | Local read/write, terminal, or stdout pipe I/O failure |
| 75 | `EX_TEMPFAIL` | Lock contention, concurrent/worktree conflict, incomplete transaction, or other condition that may succeed after caller action/retry |
| 77 | `EX_NOPERM` | Decree denial, rejected proclamation, unavailable authorized guardian, or declined security confirmation |
| 78 | `EX_CONFIG` | Malformed, unsafe, ambiguous, or unsupported Sphinx/provider configuration |

Sphinx MUST map every handled error to one of these values and MUST NOT give an existing value a different category meaning. Exit `1` is not emitted intentionally. Termination by the operating system or a signal remains outside this contract. Scripts requiring a precise cause use the JSON error code rather than parsing human text or relying on a more granular process status.

Every command except shell completion supports global `--json`. JSON mode emits exactly one UTF-8 JSON object followed by one newline, with schema version `1`, no ANSI styling, and no additional human output on that object's stream. Object keys are emitted deterministically. Prompts use the controlling terminal and therefore do not corrupt JSON output.

Successful output is written to stdout:

```json
{"version":1,"ok":true,"data":{},"warnings":[]}
```

Failed output leaves stdout empty, writes exactly one error object to stderr, and exits nonzero:

```json
{"version":1,"ok":false,"error":{"code":"authorization_denied","message":"reveal is not authorized","retryable":false}}
```

The initial stable error-code registry is: `usage`, `config_invalid`, `not_found`, `data_invalid`, `integrity_failed`, `authorization_denied`, `proclamation_rejected`, `guardian_unavailable`, `tailscale_unavailable`, `dependency_unavailable`, `worktree_conflict`, `recovery_required`, `cannot_create`, `io_error`, `confirmation_declined`, and `internal_error`. Each maps to the corresponding `sysexits` category above. `error.code` is stable lower-snake-case; `message` is human-readable and not stable. Optional `details` MUST contain only documented non-secret fields. Existing identifiers never change meaning or disappear within format version 1; new identifiers and optional object fields may be added. Consumers MUST ignore unknown fields but MUST reject an unsupported top-level `version`.

In JSON reveal mode, `data.secrets` is an object preserving schema scalar types and contains all secrets by default or exactly one entry with `--secret NAME`. This is still decrypted stdout and receives the same authorization and terminal-confirmation treatment. JSON errors, warnings, details, and diagnostics MUST never contain secret values, proclamation text, private identities, encrypted environment records, or plaintext recovered during a failed operation. `artifact inspect --json` marks inscriptions as `verified: false` and includes the stable `unverified_inscriptions` warning code.

There is no JSON Lines/streaming protocol in the initial interface. Authoring may still prompt interactively while returning its final non-secret result envelope as JSON.

## 11. Configuration

### 11.1 Optional global configuration

Sphinx follows the XDG Base Directory Specification for optional user-global configuration:

```text
$XDG_CONFIG_HOME/sphinx/config.yaml
```

If `XDG_CONFIG_HOME` is unset or not absolute, the fallback is `$HOME/.config/sphinx/config.yaml`. This behavior is the same on macOS and Linux; Sphinx does not substitute `~/Library/Application Support`. The XDG configuration directory SHOULD be mode `0700`, and the file MUST reject unsafe ownership, file types, and symlinks.

The global configuration contains manually maintained tomb aliases but no tomb lock data or guardian records:

```yaml
version: 1
tombs:
  company-secrets:
    reference: github:acme/secrets?ref=main
```

The global file is optional. If absent, direct tomb references still work with `sphinx tomb add`. No Sphinx command mutates this file.

### 11.2 Project configuration

For project operations, Sphinx discovers the current Git worktree root and reads `<root>/.sphinx/config.yaml`:

```yaml
version: 1
tombs:
  default:
    reference: github:acme/secrets?ref=main
    lock:
      commit: 83b29d47a6d5...
      proclamation_fingerprint: SHA256:5JCY3N...
      decree_generation: 12
      locked_at: 2026-03-22T12:00:00Z
    guardians:
      - name: personal-guardian
        # provider is optional; defaults to apple-icloud-keychain on macOS

# Other project-specific Sphinx configuration also lives here.
```

A CI project may select the fixed-variable environment provider:

```yaml
tombs:
  default:
    guardians:
      - name: ci
        provider: environment
```

The workflow must provide `SPHINX_GUARDIAN`; no variable name appears in configuration.

There is no `default_tomb` field: default selection is represented by the local alias `default`. Tomb aliases MUST match `[A-Za-z0-9][A-Za-z0-9._-]*` and must not be parseable as tomb references.

Project configuration is repository-visible trust and reproducibility data and SHOULD be committed. It MUST NOT contain private identities, proclamations, decrypted secrets, or embedded Git credentials. Guardian entries are ordered, guardian names are unique within each tomb, and an omitted provider canonicalizes to the macOS default before duplicate checks. Both configuration layers use strict decoding. Project settings override global defaults where a setting is explicitly designed to be overridable, but global tomb entries are aliases only and MUST NOT override a project lock.

Cache materialization follows XDG at `$XDG_CACHE_HOME/sphinx` or `$HOME/.cache/sphinx`. The cache root is mode `0700`, contains Git objects/ciphertext and no private identities or plaintext, keys immutable entries by canonical repository identity plus commit, and uses inter-process locks and atomic promotion from candidate storage. Cache corruption causes eviction/refetch or fail-closed error, never acceptance of bytes that do not match the locked commit.

## 12. Acceptance criteria

The release satisfies these acceptance criteria:

- `sphinx --help` exposes tomb, artifact, guardian, proclamation rotation, and decree management and no server/daemon command.
- No process started by Sphinx listens for Sphinx requests.
- Generated guardians pass pinned hybrid classical/PQ interoperability vectors.
- Decrees and rotation transitions use the pinned Go Ed25519 + CIRCL v1.6.3 ML-DSA-65 frame and encodings; both signatures must verify against fixed FIPS/interoperability vectors.
- Secure credential providers are the sole guardian stores; no filesystem registry or private backup file is created.
- On macOS, `apple-icloud-keychain` creates and queries synchronizable Sphinx service items, `apple-login-keychain` remains explicitly non-synchronizable, and no silent provider fallback occurs.
- The read-only `environment` provider reads only `SPHINX_GUARDIAN`, accepts exactly one matching versioned guardian record, exposes no mutating operations, and never permits configurable environment-variable names; its record format remains platform-independent.
- The initial release, signed artifact, packaging, and required CI matrix target only `darwin/arm64`. Intel macOS, Linux, and Windows artifacts are not released. Future Linux support has no persistent/default guardian provider and may use only explicit `environment` records.
- Guardian provider tests cover service/account isolation, duplicate aliases, malformed records, synchronizable filtering, fixed environment-variable behavior, multiple-environment-guardian rejection, read-only operation rejection, name/suite/derived-metadata mismatch, and synchronized deletion warnings on macOS.
- Artifact recipients use only the native `age1pq1…` ML-KEM-768 + X25519 format from filippo.io/age v1.3.1 through SOPS v3.12.1; classical, plugin, and unsupported SOPS key providers are rejected.
- Sphinx never executes or discovers age/SOPS plugin binaries, and fixed vectors interoperate with native age v1.3.1, SOPS v3.12.1, and the same-version `age-plugin-pq` test oracle.
- Every accepted artifact has exactly one proclamation recipient and zero or more unique guardian recipients, all operating independently; threshold groups, Shamir configuration, duplicate recipients, and multiple proclamation recipients are rejected.
- Proclamation derivation uses the fixed `argon2id-v1` profile (256 MiB, three iterations, four lanes, 32-byte salt/output), and initialization/rotation accepts only a Sphinx-generated ten-word phrase providing approximately 129 bits of source entropy.
- An artifact with zero guardians remains administratively accessible by proclamation but guardian-based reveal fails with a clear no-guardian error.
- Every artifact uses inherent plural `secrets` and `inscriptions` mappings; schemas define and validate their fields without changing container names or encryption policy.
- Secrets and inscriptions are top-level named scalars under the fixed initial schema field grammar; defaults, coercion, nested mappings, sequences, nulls, and binary/tagged values are rejected.
- Artifacts with multiple secrets and inscriptions round-trip and validate against a schema resolved at the same locked tomb revision.
- Create produces a proclamation-only artifact; inscription updates and reseals rotate the SOPS data key, deletion updates locks atomically, and schema references are immutable after creation in the initial release.
- Reseal replaces all secrets by default or one named secret with `--secret`, and every successful reseal rotates the SOPS data key.
- Artifact create/reseal/inscription/delete, schema edits, guardian add/remove, and decree changes fail acceptance without a valid proclamation and correspondingly updated signed exhaustive artifact/schema locks.
- Reveal performs a fresh tailscaled LocalAPI identity check, accepts login-only or tag-only seekers, and fails closed for unavailable, stopped, logged-out, disconnected, stale, overridden, or identity-less Tailscale state; no offline reveal mode exists.
- Reveal outputs all secrets by default using the specified secrets-only YAML document, exactly one canonical scalar with `--secret NAME`, or the version-1 JSON envelope in JSON mode.
- Reveal also fails closed for unlocked tombs, invalid or unlisted chambers, artifact digest mismatches, proclamation-key pin mismatch, invalid decree signatures, wrong tomb-ID binding, wrong seekers, absent guardian recipients, tampered artifact MACs, schema mismatch, and unsafe paths.
- Inspect displays readable inscriptions without proclamation, guardian, or seeker authorization and always warns that they have not been verified through the SOPS MAC.
- Decrees remain readable, are never SOPS encrypted, and cannot be accepted after modification without a valid proclamation signature.
- Decrees contain only allow rules for reveal, reject deny/effect/action fields, use the fixed anchored chamber-glob grammar, match exact Tailscale logins and `tag:` device tags with OR semantics, and default deny when no rule matches.
- Security documentation consistently describes decree enforcement as advisory and does not claim cryptographic prevention of direct guardian use outside Sphinx.
- Sphinx mutates only explicit caller-managed local tomb worktrees and never stages, commits, signs Git commits/tags, pushes, creates branches/PRs, merges, or modifies immutable caches.
- Each tomb validates as a Git repository with canonical `.tomb/tomb.yaml`, `.tomb/decree.yaml`, `.tomb/decree.yaml.sig`, `.tomb/rotations/.keep`, and `.tomb/schemas/` locations and no alternate tomb metadata paths.
- Artifact schema references use only `name/vN`, resolve to `.tomb/schemas/name/vN.yaml` at the same locked commit, and cannot reference external schemas.
- Decree signatures bind the exact tomb manifest digest, and exhaustive signed schema locks prevent unsigned schema substitution.
- Managed tomb files are exact regular Git blobs with no submodule, LFS, filter, encoding, or line-ending transformation; locked reads come from the object database.
- Chamber paths remain exact and case-sensitive; case-colliding chambers are not rejected solely for their case collision.
- Each tomb has exactly one decree whose signed artifact/schema lock lists are exhaustive, unique, bytewise sorted, and match all committed artifact and schema blobs.
- Guardian add/remove fully re-encrypts every artifact in scope with a distinct fresh SOPS data key per artifact, updates all locks/signatures atomically, and documents that removing access cannot revoke previously revealed values.
- Failed or crashed multi-file mutations restore only journaled target paths to exact pre-images, never use Git reset/index/stash/commit mechanisms, and fail closed rather than overwrite an unexpected caller edit.
- Every authorized signed-state mutation increments the decree generation exactly once; tomb update rejects lower generations and same-generation signed-state changes, preventing replay of an older valid decree/artifact set in a descendant commit.
- Proclamation rotation cross-signs a contiguous transition, rotates every artifact with a fresh data key, signs the new decree, and changes the manifest atomically; consumers advance commit, fingerprint, and generation only after validating the complete chain and candidate tomb.
- The initial release performs no hybrid-suite rotation or mixed-suite reveal; future rotation requires a separately specified bridge release and all-artifact transaction.
- Sphinx imposes no maximum size on artifacts, schemas, decrees, individual secrets, or Git repositories.
- Every YAML parser rejects anchors, aliases, custom tags, duplicate keys, multiple documents, and merge keys.
- Sphinx creates no persistent event or audit store, and black-box tests verify that interactive authoring fails without a controlling terminal or when secret/proclamation input is attempted through unsupported channels.
- Every handled failure maps to the documented stable BSD `sysexits` subset; JSON mode emits one version-1 object on stdout for success or stderr for failure, with stable error/warning identifiers and no secret-bearing error fields.
- Decrypted values are emitted only on stdout; terminal output requires confirmation, stderr never contains secrets, and clipboard/file/temporary-file/explicit-FD/exec output modes do not exist.
- Tests cover fixed Argon2id and proclamation-generation vectors, KDF-profile downgrade/resource-value rejection, crypto vectors, SOPS interoperability, tomb-reference and chamber fuzz cases, Git races, writable-worktree guards, crash injection after every transaction phase, exact-path rollback, third-party-edit refusal, corrupt-journal failure, prohibition of Git reset/stage/commit/push side effects, Tailscale resolution, policy precedence, YAML ambiguity, atomic writes, and macOS CLI black-box flows.
- Documentation and examples consistently use artifact, chamber, secret, proclamation, guardian, seeker, tomb, tomb reference, schema, inscription, and decree.
- `go test ./...`, race/static checks, and `nix flake check` pass on all supported targets.
