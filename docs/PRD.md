# Sphinx Product Requirements Document

## 1. Summary

Sphinx is a small identity-aware secrets-management system. A Sphinx daemon guards a Tomb containing SOPS-encrypted Relics. A Seeker or Envoy answers a Riddle through Tailscale identity, Sphinx evaluates its Decrees, and every Judgment is recorded in the Chronicle.

The first Temple is a Mac running Sphinx as a per-user LaunchAgent. Its age private identity is held in the macOS login Keychain. The daemon is reachable only through a private Tailscale network. Sphinx trusts the identity reported by Tailscale and does not depend on a specific tailnet identity provider.

A Tomb may be either a local directory or a Git repository, including a private GitHub repository. Sphinx itself is developed publicly and contains no production Tomb, private identity, or secret material.

[`TERMINOLOGY.md`](TERMINOLOGY.md) is normative for product language. Conventional names remain appropriate for low-level cryptography and implementation details.

## 2. Product components

### Sphinx client

The `sphinx` command-line client submits Petitions to a Sphinx daemon, manages the local Keychain identity, and authors schema-driven Relics.

```console
sphinx key init
sphinx relic entomb --schema anthropic-api-key/v1 services/anthropic
sphinx relic reveal --facet api_key services/anthropic --server https://sphinx.example.ts.net
```

### Sphinx daemon

The same executable runs the daemon:

```console
sphinx guard \
  --tomb github:example/secrets-tomb \
  --tomb-ref main \
  --tomb-path secrets \
  --decree ./decree.yaml
```

The daemon materializes the Tomb, verifies caller identity, evaluates Decrees, unseals authorized Relics in memory, and appends Chronicle Entries.

### Tomb

A Tomb is a versioned collection of sealed Relics. It can be:

- A local directory, such as `/Users/example/secrets`.
- A GitHub repository shorthand, such as `github:owner/repository`.
- A Git URL prefixed with `git+`, using HTTPS or SSH.

A relative path inside a Git checkout may be selected with `--tomb-path`. A branch, tag, or commit may be selected with `--tomb-ref`.

## 3. Goals

- Remove GPG and GPG keyring handling from runtime access.
- Encrypt and decrypt structured SOPS YAML using age entirely in process.
- Keep the online Sphinx age identity in macOS Keychain, never in a Tomb, environment variable, command argument, or temporary file.
- Wrap each Relic data key for exactly one online X25519 recipient and one user-chosen age-scrypt recovery passphrase.
- Keep the SOPS encryption policy internal to Sphinx without a Tomb `.sops.yaml`.
- Prompt for structured Essence and Inscription fields from versioned Tomb schemas.
- Support local and remote Git Tombs without coupling Sphinx to one secret repository.
- Authenticate every Relic Petition with Tailscale LocalAPI `WhoIs`.
- Treat the identity-provider-agnostic Tailscale login as the v1 Seeker identity.
- Authorize Relic paths using a small, reviewable Decree file.
- Return only a Relic's Essence, not its complete decrypted document.
- Record every allow or deny Judgment without recording Essence.
- Bind to loopback and rely on Tailscale Serve for private HTTPS exposure.
- Fail closed when Keychain, Git, Tailscale identity, Decree evaluation, SOPS integrity, or path validation fails.

## 4. Non-goals for v1

- Public internet exposure or Tailscale Funnel.
- A web interface.
- Creating, editing, or committing Relics through the network API; authoring commands operate on a local Tomb.
- Automatically refreshing a remote Tomb while the daemon is running.
- Direct identity-provider OAuth, organization/group queries, or workload OIDC.
- Serving multiple Tombs from one daemon process.
- High availability, multi-host consensus, or remote KMS.
- Preventing an authorized caller from retaining Essence after revelation.

## 5. Security model

### Trust boundaries

- **Identity provider and Tailscale control plane:** establish the tailnet identity.
- **tailscaled LocalAPI:** maps a connection to a trusted login, node, and tags.
- **Decree:** maps trusted identities and node tags to Relic path patterns.
- **macOS Keychain:** protects the online Sphinx age identity at rest.
- **Recovery passphrase:** lets an operator recover Relics locally without the online identity.
- **Git Tomb:** supplies versioned schemas and encrypted documents at a selected revision.
- **SOPS:** authenticates and encrypts or decrypts each Relic document.

### Assumptions

- Tailscale Serve has Funnel disabled and accepts only tailnet traffic.
- The login session and login Keychain are unlocked when the LaunchAgent starts.
- FileVault is enabled and the Temple is maintained as a trusted host.
- Tomb writers are trusted secret administrators. A writer can replace encrypted Essence because the age recipient is public.
- The Decree is controlled separately from the Tomb, preventing Tomb writers from granting themselves Passage.
- A strong user-chosen recovery passphrase is retained offline and is never generated or stored by Sphinx.
- Private Git credentials are available non-interactively to the LaunchAgent through SSH or a secure Git credential helper.

### Known limitations

- The age identity and revealed Essence exist in process memory while needed.
- Malware with the Temple user's privileges may call Sphinx or capture results.
- Static third-party credentials remain usable after retrieval until provider rotation.
- Tailscale or identity-provider compromise may grant Passage allowed by Decrees.
- Branches and tags are mutable. High-value deployments should use a pinned commit or establish signed-commit verification in a future release.
- A remote Tomb is fetched at daemon startup; updates require a restart in v1.

## 6. Functional requirements

### Key management

- `sphinx key init` generates the online X25519 age identity and stores it as a generic-password Keychain item.
- `sphinx key recipient` prints only the online public age recipient.
- Initialization refuses to overwrite an existing identity.
- The default Keychain service is `dev.marksisson.sphinx.age`; the account is `sphinx-v1`.
- Recovery uses age's built-in scrypt recipient with a passphrase read from a terminal with echo disabled.
- Sphinx never generates, stores, logs, or accepts the recovery passphrase through arguments or environment variables.
- `.sphinx/tomb.yaml` binds a Tomb to one online recipient and contains only an encrypted recovery check, never the passphrase.

### Tomb materialization

- `--tomb PATH` opens a local Tomb.
- `--tomb github:OWNER/REPOSITORY` clones or updates a GitHub Tomb over HTTPS.
- `--tomb git+https://…` and `--tomb git+ssh://…` clone or update generic Git Tombs.
- `--tomb-ref REF` selects a validated branch, tag, or commit; remote `HEAD` is the default.
- `--tomb-path PATH` selects a relative directory inside the checkout; `.` is the default.
- Remote Tombs are cached below the user's cache directory with mode `0700`.
- Git runs non-interactively and a credential must never be embedded in a Tomb URL.
- Checkout paths and symlinks must not escape the cached repository.
- Sphinx logs the resolved commit but never logs credentials or Essence.

### Schemas and Relic authoring

- Schemas are declarative YAML documents below `.sphinx/schemas/` and cannot execute commands or templates.
- A schema versions and defines typed Essence and Inscription fields.
- `sphinx relic entomb` creates `PATH/relic.yaml`, refuses overwrite, and requires the recovery passphrase.
- `sphinx relic reseal` replaces the Essence, verifies the recovery passphrase, and rotates the SOPS data key.
- `sphinx relic inscribe` updates only non-secret metadata while retaining the data key and both recipient envelopes.
- `sphinx relic inspect` displays only the schema and Inscription.
- Sphinx always encrypts the complete `essence` branch and does not permit schemas to alter encryption policy.
- Writes use a mode-`0600` temporary file and atomic rename.

### Relic revelation

- `GET /v1/relics/{path}` reads `${TOMB_ROOT}/{path}/relic.yaml`.
- Paths contain only slash-separated `[A-Za-z0-9._-]+` segments.
- Absolute paths, empty segments, symlink escapes, `.` and `..` are rejected.
- The SOPS MAC is verified before Essence is returned.
- Only age encryption is serviced; there is no GPG fallback.
- The response is JSON containing `essence`.
- `?field=NAME` and CLI `--facet NAME` return one schema-defined Essence field.
- `sphinx relic reveal --recovery` decrypts a local Tomb using a securely prompted passphrase and does not contact the daemon.

### Riddle and Judgment

- Every `/v1/relics` request is resolved through Tailscale LocalAPI `WhoIs` using the actual remote address.
- Decrees may match Tailscale login names and node tags.
- Passage is granted when one Decree matches both identity and Relic path.
- No matching Decree means refusal.
- `/healthz` reveals no Tomb, identity, or Relic information.

### Chronicle

Each Petition records:

- UTC timestamp
- request ID
- login when available
- node and tags when available
- requested Relic path and optional Facet
- allow or deny Judgment
- non-sensitive reason

Chronicle Entries never contain Essence, decrypted documents, age identities, Git credentials, or authorization headers.

## 7. Decree format

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
- Maximum encrypted Relic size: 1 MiB.
- Responses set `Cache-Control: no-store`.
- HTTP server timeouts are configured.
- Chronicle files and locally authored `relic.yaml` files are created with mode `0600`.
- Tomb caches and newly created Relic directories are created with mode `0700`.
- Shutdown is graceful on `SIGINT` or `SIGTERM`.
- The daemon runs as a LaunchAgent, not root or a system daemon.

## 9. Migration from PGP to age

1. Run `sphinx key init` and record the online recipient.
2. Choose and securely retain a strong recovery passphrase; Sphinx does not generate one.
3. Define the destination Relic schemas below `.sphinx/schemas/`.
4. Decrypt each existing PGP Relic in a controlled environment and pass its values directly to `sphinx relic entomb` without a plaintext temporary file.
5. Verify both online and `--recovery` revelation before removing the PGP recipient.
6. Archive the PGP private key for a defined rollback period, then destroy it.

Migration is never automatic because it requires the existing PGP private key, schema selection, and an explicit recovery decision.

## 10. Future work

- `sphinx relic exec` with stdin or file-descriptor delivery.
- Periodic Tomb refresh with atomic revision swaps.
- Signed-commit or allow-listed-commit verification.
- Multiple named Tombs per daemon.
- Direct identity-provider OAuth and short-lived Sphinx sessions.
- Workload OIDC for Envoys.
- Identity-provider organization/group Decrees.
- Signed/notarized binary-bound Keychain access controls.
- Hardware-backed recovery through an age plugin.
- Tamper-evident remote Chronicle sink.

## 11. Acceptance criteria

- Sphinx is maintained in a public repository containing no operational Tomb or private identity.
- No Sphinx code invokes GPG or requires `SOPS_AGE_KEY_FILE`.
- Keychain identity material is used directly in memory without an identity file.
- New Relics contain one online age wrapping and one age-scrypt recovery wrapping.
- Tombs require no `.sops.yaml`; encryption selection cannot be changed by a schema.
- Local, GitHub, HTTPS Git, and SSH Git Tomb references are parsed safely.
- A remote Tomb is checked out at a known commit in a private cache.
- An authorized Tailscale identity can reveal an age-encrypted Relic.
- Unauthorized identities, malformed paths, modified ciphertext, PGP-only files, unsafe Git references, and checkout escapes fail closed.
- Tests cover Tomb parsing/materialization and configuration, schemas, path validation, glob matching, authorization, and online/recovery SOPS age/MAC verification.
- `nix flake check` builds and tests Sphinx on the current Darwin system.
