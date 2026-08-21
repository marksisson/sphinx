# sphinx

sphinx is an identity-aware guardian that controls access to relics.

> A **sphinx** guards **tombs**. tombs contain **chambers**, and chambers hold **relics**. A **seeker** or **envoy** answers a **riddle** to prove its identity. **decrees** determine whether passage is granted, and each judgment is recorded in the **chronicle**.

See the [PRD](docs/PRD.md), [relic schema guide](docs/SCHEMAS.md), and [canonical terminology](docs/TERMINOLOGY.md).

## Status

This is an early MVP for a Mac temple on a private Tailscale network. It supports:

- macOS Keychain storage for sphinx's guardian private key
- schema-driven `entomb`, `inspect`, `inscribe`, `reseal`, and `reveal` commands
- authenticated in-process encryption and decryption
- Keychain-backed guardian-key decryption plus user-chosen passphrase recovery
- schema- and relic-aware shell completion
- local directories and explicitly locked remote Git repositories as tombs
- tomb locators with GitHub and Git branch, tag, commit, pull-request, and subdirectory selectors
- named tomb configuration plus explicit `tomb update`, `tomb status`, and `tomb protect` lifecycle commands
- Tailscale `WhoIs` as an identity-provider-agnostic riddle
- path-based decrees
- JSONL chronicle entries
- structured essence facets and non-secret inscriptions


## Build and test

```console
nix flake check
nix build
```

Or run directly from GitHub:

```console
nix run github:marksisson/sphinx -- help
```

## awaken the guardian

```console
nix run . -- guardian awaken
nix run . -- guardian behold
```

`guardian awaken` generates the guardian's private key, stores it in the login Keychain, and prints its public key. `guardian behold` prints the public key again. sphinx never generates or stores the tomb recovery passphrase; the user supplies it securely when entombing or resealing a relic.

## Write a decree

```console
cp decree.example.yaml decree.yaml
chmod 600 decree.yaml
```

Replace the example login with the `LoginName` reported by Tailscale for the seeker. Keep the operational decree outside the tomb so tomb writers cannot grant themselves passage.

## Define a schema and entomb a relic

Each tomb stores declarative schemas below `.sphinx/schemas/`. For example:

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

Create the first relic interactively:

```console
nix run . -- relic entomb \
  --tomb /absolute/path/to/secrets \
  --schema anthropic-api-key/v1 \
  services/anthropic
```

sphinx securely prompts for essence fields and for a user-chosen recovery passphrase. The first `entomb` creates `.sphinx/tomb.yaml`, which binds the tomb to exactly one guardian public key and one passphrase recovery mechanism. Every relic is stored as `PATH/relic.yaml`.

Administrative operations are:

```console
sphinx relic inspect services/anthropic
sphinx relic inscribe services/anthropic
sphinx relic reseal services/anthropic
```

`inspect` shows only the schema and non-secret inscription. `inscribe` retains the essence and recovery wrapping. `reseal` replaces the essence, verifies the recovery passphrase, and rotates the relic data key.

## Configure and protect a tomb

Copy the operational configuration outside the tomb and restrict its permissions:

```console
mkdir -p "$HOME/Library/Application Support/sphinx"
cp sphinx.example.yaml "$HOME/Library/Application Support/sphinx/config.yaml"
chmod 600 "$HOME/Library/Application Support/sphinx/config.yaml"
```

A configuration can define multiple named tombs and one default:

```yaml
version: 1
default_tomb: production
tombs:
  production:
    locator: github:example/secrets-tomb/main?dir=secrets
    lock: ./production.tomb.lock.yaml
    decree: ./decree.yaml
    chronicle: ~/Library/Logs/sphinx-production.jsonl
    listen: 127.0.0.1:8787
```

For a remote tomb, explicitly resolve, validate, and approve the mutable tomb
locator before protecting it:

```console
sphinx tomb update production
sphinx tomb status production
sphinx tomb protect production
```

`tomb update` is the only command that advances the mode-`0600` lock. It
materializes the candidate, validates the tomb configuration, schemas, relic
headers, public-key bindings, paths, symlinks, and size limits, then records the
resolved commit. `tomb protect` ignores mutable branch movement and serves only
the exact locked commit. A daemon restart is required to serve a newly approved
lock in v1.

tomb locators use a deliberately restricted syntax:

```text
github:OWNER/REPOSITORY
github:OWNER/REPOSITORY/BRANCH-OR-TAG
github:OWNER/REPOSITORY/pull/123/head
github:OWNER/REPOSITORY/FULL-COMMIT
github:OWNER/REPOSITORY/main?dir=secrets
git+https://github.com/OWNER/REPOSITORY.git?ref=main&dir=secrets
git+ssh://git@github.com/OWNER/REPOSITORY.git?ref=main
```

Generic HTTP files and tarballs are not accepted. Private HTTPS tombs require a
configured Git credential helper. Private SSH tombs require non-interactive SSH
credentials available to the LaunchAgent. Local tomb locators can be filesystem
paths and do not need a lock.

## reveal a relic

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

reveal one structured essence facet with `--facet`:

```console
nix run . -- relic reveal --facet api_key services/anthropic
```

Recovery bypasses the daemon and decrypts a local tomb after a secure passphrase prompt:

```console
nix run . -- relic reveal \
  --recovery \
  --tomb /absolute/path/to/secrets \
  --facet api_key \
  services/anthropic
```

The client prints essence to stdout. Treat terminal scrollback and redirected output as sensitive. A future `relic exec` operation will reduce accidental exposure.

## Shell completion

```console
source <(sphinx completion zsh)
```

Completion is available for bash, zsh, fish, and PowerShell. It discovers schema references, existing relic paths, and schema-defined essence facets.

## Run as a LaunchAgent

1. Run sphinx interactively so macOS can grant Keychain access.
2. Adapt `launchd/dev.marksisson.sphinx.plist.example`.
3. Configure Tailscale Serve to expose `127.0.0.1:8787` privately over HTTPS.
4. Keep Tailscale Funnel disabled and restrict access with tailnet ACLs.

## Security properties

- The API fails closed when Tailscale cannot identify a petitioner.
- Only sphinx's configured encryption format is handled.
- The guardian private key is loaded from Keychain without a private-key file or environment variable.
- Recovery uses a passphrase read from a terminal with echo disabled.
- Every tomb is bound to one guardian public key and one recovery passphrase mechanism.
- sphinx owns its encryption policy internally; tombs cannot override it.
- tomb locators, Git refs, checkout subdirectories, and symlinks are validated; tarballs and generic HTTP locators are rejected.
- Remote tombs fail closed without a matching lock, and protection checks the materialized commit against the locked revision.
- Mutable update candidates and immutable protected revisions use separate checkouts.
- Every allow or deny judgment is appended to the chronicle.
- chronicle entries never contain essence.
