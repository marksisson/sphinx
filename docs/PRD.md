# sphinx Product Requirements Document

## 1. Summary

sphinx is a small identity-aware secrets-management system. A sphinx daemon guards a tomb containing relics. A seeker or envoy answers a riddle through Tailscale identity, sphinx evaluates its decrees, and every judgment is recorded in the chronicle.

The first temple is a Mac running sphinx as a per-user LaunchAgent. Its guardian private key is held in the macOS login Keychain. The daemon is reachable only through a private Tailscale network. sphinx trusts the identity reported by Tailscale and does not depend on a specific tailnet identity provider.

A tomb may be either a local directory or a Git repository, including a private GitHub repository. sphinx itself is developed publicly and contains no production tomb, private key, or secret material.

[`TERMINOLOGY.md`](TERMINOLOGY.md) is normative for product language. Conventional names remain appropriate for low-level cryptography and implementation details.

## 2. Product components

### sphinx client

The `sphinx` command-line client submits petitions to a sphinx daemon, manages the local private key in Keychain, and authors schema-driven relics.

```console
sphinx guardian awaken
sphinx relic entomb --schema anthropic-api-key/v1 services/anthropic
sphinx relic reveal --facet api_key services/anthropic --server https://sphinx.example.ts.net
```

### sphinx daemon

The same executable runs the daemon:

```console
sphinx tomb update production
sphinx tomb protect production
```

The daemon materializes the tomb, verifies caller identity, evaluates decrees, unseals authorized relics in memory, and appends chronicle entries.

### tomb

A tomb is a versioned collection of sealed relics. It can be:

- A local directory, such as `/Users/example/secrets`.
- A GitHub repository shorthand, such as `github:owner/repository`.
- A Git URL prefixed with `git+`, using HTTPS or SSH.

Operational configuration names each tomb's locator, lock, decree, chronicle, cache, listener, and guardian Keychain item. The locator carries any mutable tracking ref or checkout subdirectory. Remote tombs must be explicitly resolved and approved with `sphinx tomb update`; protection serves only the immutable commit recorded in the lock.

## 3. Goals

- Encrypt and decrypt structured YAML entirely in process.
- Keep the guardian private key in macOS Keychain, never in a tomb, environment variable, command argument, or temporary file.
- Wrap each relic data key for exactly one guardian X25519 public key and one user-chosen recovery passphrase.
- Keep the encryption policy internal to sphinx so a tomb cannot override it.
- Prompt for structured essence and inscription fields from versioned tomb schemas.
- Support local and remote Git tombs without coupling sphinx to one secret repository.
- Identify and authenticate the petitioner for every relic petition with Tailscale LocalAPI `WhoIs`.
- Treat the identity-provider-agnostic Tailscale login as the v1 seeker identity.
- Authorize relic paths using a small, reviewable decree file.
- Return only a relic's essence, not its complete decrypted document.
- Record every allow or deny judgment without recording essence.
- Bind to loopback and rely on Tailscale Serve for private HTTPS exposure.
- Fail closed when Keychain, Git, Tailscale identity, decree evaluation, encrypted-document integrity, or path validation fails.

## 4. Non-goals for v1

- Public internet exposure or Tailscale Funnel.
- A web interface.
- Creating, editing, or committing relics through the network API; authoring commands operate on a local tomb.
- Automatically refreshing a remote tomb while the daemon is running.
- Direct identity-provider OAuth, organization/group queries, or workload OIDC.
- Serving multiple tombs from one daemon process.
- High availability, multi-host consensus, or remote KMS.
- Preventing an authorized caller from retaining essence after revelation.

## 5. Security model

### Trust boundaries

- **Identity provider and Tailscale control plane:** establish the tailnet identity.
- **tailscaled LocalAPI:** maps a connection to a trusted login, node, and tags.
- **decree:** maps trusted identities and node tags to relic path patterns.
- **macOS Keychain:** protects the guardian private key at rest.
- **Recovery passphrase:** lets an operator recover relics locally without the guardian private key.
- **Git tomb:** supplies versioned schemas and encrypted documents at a selected revision.
- **Encryption layer:** authenticates and encrypts or decrypts each relic document.

### Assumptions

- Tailscale Serve has Funnel disabled and accepts only tailnet traffic.
- The login session and login Keychain are unlocked when the LaunchAgent starts.
- FileVault is enabled and the temple is maintained as a trusted host.
- tomb writers are trusted secret administrators. A writer can replace encrypted essence because the guardian public key is available.
- The decree is controlled separately from the tomb, preventing tomb writers from granting themselves passage.
- A strong user-chosen recovery passphrase is retained offline and is never generated or stored by sphinx.
- Private Git credentials are available non-interactively to the LaunchAgent through SSH or a secure Git credential helper.

### Known limitations

- The guardian private key and revealed essence exist in process memory while needed.
- Malware with the temple user's privileges may call sphinx or capture results.
- Static third-party credentials remain usable after retrieval until provider rotation.
- Tailscale or identity-provider compromise may grant passage allowed by decrees.
- Branches and tags are mutable update channels. `tomb update` records their resolved commit in a separate lock, but it does not yet authenticate the commit's signer.
- A remote tomb is fetched at daemon startup at exactly its locked revision; approving and serving updates requires `tomb update` followed by a restart in v1.

## 6. Functional requirements

### guardian key management

- `sphinx guardian awaken` generates the guardian's X25519 private key and stores it as a generic-password Keychain item.
- `sphinx guardian behold` prints only the guardian's public key.
- Initialization refuses to overwrite an existing private key.
- The default Keychain service is `dev.marksisson.sphinx.keys`; the account is `sphinx-v1`.
- Recovery uses a passphrase read from a terminal with echo disabled.
- sphinx never generates, stores, logs, or accepts the recovery passphrase through arguments or environment variables.
- `.sphinx/tomb.yaml` binds a tomb to one guardian public key and contains only an encrypted recovery check, never the passphrase.

### tomb materialization

- The operational configuration supports multiple named tombs and one default tomb.
- A local filesystem tomb locator opens a local tomb without a revision lock.
- `github:OWNER/REPOSITORY[/REF]` selects GitHub, including slash-containing refs such as `pull/123/head`.
- `git+https://…` and `git+ssh://…` select generic Git repositories.
- `ref`, `rev`, and `dir` selectors are encoded only in the tomb locator; separate configuration fields are rejected.
- Generic HTTP locators, tarballs, embedded credentials, unknown query parameters, unsafe refs, and escaping directories are rejected.
- `sphinx tomb update` materializes and validates a candidate before atomically writing a mode-`0600` lock with the full resolved commit.
- `sphinx tomb protect` requires a matching lock and checks out exactly its full commit; it never advances a mutable ref.
- Candidate and immutable revision checkouts are separate so an update cannot mutate a running locked tomb.
- Remote tombs are cached below the user's cache directory with mode `0700`.
- Git runs non-interactively, and checkout paths and symlinks must not escape the cached repository.
- sphinx logs the resolved commit but never logs credentials or essence.

### Schemas and relic authoring

- Schemas are declarative YAML documents below `.sphinx/schemas/` and cannot execute commands or templates.
- A schema versions and defines typed essence and inscription fields.
- `sphinx relic entomb` creates `PATH/relic.yaml`, refuses overwrite, and requires the recovery passphrase.
- `sphinx relic reseal` replaces the essence, verifies the recovery passphrase, and rotates the relic data key.
- `sphinx relic inscribe` updates only non-secret metadata while retaining the data key and both key wrappings.
- `sphinx relic inspect` displays only the schema and inscription.
- sphinx always encrypts the complete `essence` branch and does not permit schemas to alter encryption policy.
- Writes use a mode-`0600` temporary file and atomic rename.

### relic revelation

- `GET /v1/relics/{path}` reads `${TOMB_ROOT}/{path}/relic.yaml`.
- Paths contain only slash-separated `[A-Za-z0-9._-]+` segments.
- Absolute paths, empty segments, symlink escapes, `.` and `..` are rejected.
- The MAC is verified before essence is returned.
- Only sphinx's current encryption format is serviced.
- The response is JSON containing `essence`.
- `?field=NAME` and CLI `--facet NAME` return one schema-defined essence field.
- `sphinx relic reveal --recovery` decrypts a local tomb using a securely prompted passphrase and does not contact the daemon.

### riddle and judgment

- Every `/v1/relics` request is resolved through Tailscale LocalAPI `WhoIs` using the actual remote address.
- decrees may match Tailscale login names and node tags.
- passage is granted when one decree matches both identity and relic path.
- No matching decree means refusal.
- `/healthz` reveals no tomb, identity, or relic information.

### chronicle

Each petition records:

- UTC timestamp
- request ID
- login when available
- node and tags when available
- requested relic path and optional facet
- allow or deny judgment
- non-sensitive reason

chronicle entries never contain essence, decrypted documents, guardian private keys, Git credentials, or authorization headers.

## 7. decree format

```yaml
version: 1
rules:
  - name: personal-admin
    paths:
      - "**"
    tailscale:
      logins:
        - "user@example.com"
      tags: []
```

Path patterns support `*` within one segment and `**` across segments. A rule with both logins and tags accepts a principal matching either list. Empty identity lists match nobody.

## 8. Operational requirements

- Default listen address: `127.0.0.1:8787`.
- Default request timeout: 15 seconds.
- Maximum encrypted relic size: 1 MiB.
- Responses set `Cache-Control: no-store`.
- HTTP server timeouts are configured.
- chronicle files and locally authored `relic.yaml` files are created with mode `0600`.
- tomb caches and newly created relic directories are created with mode `0700`.
- Shutdown is graceful on `SIGINT` or `SIGTERM`.
- The daemon runs as a LaunchAgent, not root or a system daemon.

## 9. Future work

- `sphinx relic exec` with stdin or file-descriptor delivery.
- Periodic tomb refresh with atomic revision swaps.
- Signed-commit signer verification for tomb updates.
- Multiple named tombs per daemon.
- Direct identity-provider OAuth and short-lived sphinx sessions.
- Workload OIDC for envoys.
- Identity-provider organization/group decrees.
- Signed/notarized binary-bound Keychain access controls.
- Hardware-backed recovery through a cryptographic plugin.
- Tamper-evident remote chronicle sink.

## 10. Acceptance criteria

- sphinx is maintained in a public repository containing no operational tomb or private key.
- sphinx does not load private keys from environment variables.
- Keychain private-key material is used directly in memory without a private-key file.
- New relics contain one guardian public-key wrapping and one passphrase recovery wrapping.
- Encryption selection cannot be changed by a schema or tomb configuration.
- Local, GitHub, HTTPS Git, and SSH Git tomb references are parsed safely.
- A remote tomb update is explicitly locked, and protection checks out exactly the approved commit in a private cache.
- An authorized Tailscale identity can reveal an encrypted relic.
- Unauthorized identities, malformed paths, modified ciphertext, unsupported encryption formats, unsafe Git references, and checkout escapes fail closed.
- Tests cover tomb parsing/materialization and configuration, schemas, path validation, glob matching, authorization, and guardian-key/passphrase decryption with MAC verification.
- `nix flake check` builds and tests sphinx on the current Darwin system.
