# Sphinx

Sphinx is an identity-aware guardian for SOPS-encrypted secrets.

> A **Sphinx** guards **Tombs**. Tombs contain **Chambers**, and Chambers hold **Relics**. A **Seeker** or **Envoy** answers a **Riddle** to prove its identity. **Decrees** determine whether Passage is granted, and each Judgment is recorded in the **Chronicle**.

See the [PRD](docs/PRD.md), [Relic schema guide](docs/SCHEMAS.md), and [canonical terminology](docs/TERMINOLOGY.md).

## Status

This is an early MVP for a Mac Temple on a private Tailscale network. It supports:

- macOS Keychain storage for Sphinx's age identity
- schema-driven `entomb`, `inspect`, `inscribe`, `reseal`, and `reveal` commands
- in-process SOPS/age encryption, decryption, and MAC verification
- Keychain-backed online decryption plus user-chosen age-scrypt recovery
- schema- and Relic-aware shell completion
- local directories and remote Git repositories as Tombs
- GitHub repository shorthand
- Tailscale `WhoIs` as an identity-provider-agnostic Riddle
- path-based Decrees
- JSONL Chronicle entries
- structured Essence facets and non-secret Inscriptions

Existing PGP Relics must be explicitly migrated before Sphinx can unseal them.

## Build and test

```console
nix flake check
nix build
```

Or run directly from GitHub:

```console
nix run github:marksisson/sphinx -- help
```

## Initialize Sphinx

```console
nix run . -- key init
nix run . -- key recipient
```

`key init` stores the online age identity in the login Keychain and prints its public recipient. Sphinx never generates or stores the Tomb recovery passphrase; the user supplies it securely when entombing or resealing a Relic.

## Write a Decree

```console
cp decree.example.yaml decree.yaml
chmod 600 decree.yaml
```

Replace the example login with the `LoginName` reported by Tailscale for the Seeker. Keep the operational Decree outside the Tomb so Tomb writers cannot grant themselves Passage.

## Define a schema and entomb a Relic

Each Tomb stores declarative schemas below `.sphinx/schemas/`. For example:

```yaml
name: anthropic-api-key
version: 1
description: Anthropic API credential
essence:
  - name: api_key
    type: string
    required: true
    prompt: Anthropic API key
inscription:
  - name: environment
    type: enum
    values: [development, staging, production]
    required: true
```

Create the first Relic interactively:

```console
nix run . -- relic entomb \
  --tomb /absolute/path/to/secrets \
  --schema anthropic-api-key/v1 \
  services/anthropic
```

Sphinx securely prompts for Essence fields and for a user-chosen recovery passphrase. The first `entomb` creates `.sphinx/tomb.yaml`, which binds the Tomb to exactly one online recipient and one age-scrypt recovery mechanism. Every Relic is stored as `PATH/relic.yaml`; no `.sops.yaml` is used.

Administrative operations are:

```console
sphinx relic inspect services/anthropic
sphinx relic inscribe services/anthropic
sphinx relic reseal services/anthropic
```

`inspect` shows only the schema and non-secret Inscription. `inscribe` retains the Essence and recovery wrapping. `reseal` replaces the Essence, verifies the recovery passphrase, and rotates the SOPS data key.

## Guard a local Tomb

If the supplied path is already the Relic root:

```console
nix run . -- serve \
  --tomb /absolute/path/to/secrets \
  --decree "$PWD/decree.yaml" \
  --chronicle "$HOME/Library/Logs/sphinx-chronicle.jsonl"
```

## Guard a GitHub Tomb

```console
nix run . -- serve \
  --tomb github:example/secrets-tomb \
  --tomb-ref main \
  --tomb-path secrets \
  --decree "$PWD/decree.yaml" \
  --chronicle "$HOME/Library/Logs/sphinx-chronicle.jsonl"
```

Other supported forms are:

```text
git+https://github.com/OWNER/REPOSITORY.git
git+ssh://git@github.com/OWNER/REPOSITORY.git
```

Remote Tombs are fetched non-interactively at startup and checked out at a detached commit in `~/Library/Caches/sphinx/tombs` by default. Private HTTPS Tombs require a configured Git credential helper. Private SSH Tombs require non-interactive SSH credentials available to the LaunchAgent.

The v1 daemon refreshes a remote Tomb only when restarted.

## Reveal a Relic

Locally:

```console
nix run . -- relic reveal openai/api/key
```

Through private Tailscale Serve:

```console
nix run . -- relic reveal \
  --server https://YOUR-TEMPLE.YOUR-TAILNET.ts.net \
  openai/api/key
```

Reveal one structured Essence facet with `--facet`:

```console
nix run . -- relic reveal --facet api_key services/anthropic
```

Recovery bypasses the daemon and decrypts a local Tomb after a secure passphrase prompt:

```console
nix run . -- relic reveal \
  --recovery \
  --tomb /absolute/path/to/secrets \
  --facet api_key \
  services/anthropic
```

The client prints Essence to stdout. Treat terminal scrollback and redirected output as sensitive. A future `relic exec` operation will reduce accidental exposure.

## Shell completion

```console
source <(sphinx completion zsh)
```

Completion is available for bash, zsh, fish, and PowerShell. It discovers schema references, existing Relic paths, and schema-defined Essence facets.

## Run as a LaunchAgent

1. Run Sphinx interactively so macOS can grant Keychain access.
2. Adapt `launchd/dev.marksisson.sphinx.plist.example`.
3. Configure Tailscale Serve to expose `127.0.0.1:8787` privately over HTTPS.
4. Keep Tailscale Funnel disabled and restrict access with tailnet ACLs.

## Security properties

- The API fails closed when Tailscale cannot identify a Petition.
- Only age encryption is handled; there is no GPG fallback.
- The online age identity is loaded from Keychain without an identity file or environment variable.
- Recovery uses age's built-in scrypt recipient and a passphrase read from a terminal with echo disabled.
- Every Tomb is bound to one online recipient and one recovery passphrase mechanism.
- Sphinx owns its SOPS encryption policy internally; Tombs do not need `.sops.yaml`.
- Tomb paths, Git references, checkout subdirectories, and symlinks are validated.
- Every allow or deny Judgment is appended to the Chronicle.
- Chronicle entries never contain Essence.
