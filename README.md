# Sphinx

Sphinx is an identity-aware guardian for SOPS-encrypted secrets.

> A **Sphinx** guards **Tombs**. Tombs contain **Chambers**, and Chambers hold **Relics**. A **Seeker** or **Envoy** answers a **Riddle** to prove its identity. **Decrees** determine whether Passage is granted, and each Judgment is recorded in the **Chronicle**.

See the [PRD](docs/PRD.md) and [canonical terminology](docs/TERMINOLOGY.md).

## Status

This is an early MVP for a Mac Temple on a private Tailscale network. It supports:

- macOS Keychain storage for Sphinx's age identity
- in-process SOPS/age decryption and MAC verification
- local directories and remote Git repositories as Tombs
- GitHub repository shorthand
- Tailscale `WhoIs` as a GitHub-backed Riddle
- path-based Decrees
- JSONL Chronicle entries
- a basic Relic revelation client

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

`key init` stores a new age identity in the login Keychain and prints its public recipient. Create a separate recovery identity before migrating a Tomb.

## Write a Decree

```console
cp decree.example.yaml decree.yaml
chmod 600 decree.yaml
```

Replace the example login with the `LoginName` reported by Tailscale for the Seeker. Keep the operational Decree outside the Tomb so Tomb writers cannot grant themselves Passage.

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

The client prints Essence to stdout. Treat terminal scrollback and redirected output as sensitive. A future `relic exec` operation will reduce accidental exposure.

## Run as a LaunchAgent

1. Run Sphinx interactively so macOS can grant Keychain access.
2. Adapt `launchd/dev.marksisson.sphinx.plist.example`.
3. Configure Tailscale Serve to expose `127.0.0.1:8787` privately over HTTPS.
4. Keep Tailscale Funnel disabled and restrict access with tailnet ACLs.

## Security properties

- The API fails closed when Tailscale cannot identify a Petition.
- Only age SOPS master keys are handled; there is no GPG fallback.
- The age identity is injected into SOPS in memory without an identity file or environment variable.
- Tomb paths, Git references, checkout subdirectories, and symlinks are validated.
- Every allow or deny Judgment is appended to the Chronicle.
- Chronicle entries never contain Essence.
