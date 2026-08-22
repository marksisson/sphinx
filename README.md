# Sphinx

Sphinx is a macOS Apple Silicon command-line tool for storing schema-conforming encrypted artifacts in Git tombs and revealing their secrets to authorized Tailscale seekers.

The initial release is synchronous and local. It has no network listener, background process, persistent identity cache, or local event log. Every reveal verifies the project’s exact commit lock, proclamation trust chain, signed decree, exhaustive artifact and schema hashes, fresh tailscaled LocalAPI identity, guardian recipient, SOPS MAC, and schema before writing plaintext only to stdout.

## Platform

- macOS on Apple Silicon (`darwin/arm64`)
- Git
- tailscaled running and connected for every reveal

Runtime artifact cryptography is native and in-process. External age and SOPS programs are not used.

## Build

```sh
nix build
nix run . -- --help
```

The flake exports packages, apps, checks, development shells, and a formatter only for `aarch64-darwin`.

## Core model

- A **tomb** is a Git repository.
- A **chamber** is an exact case-sensitive path containing `artifact.yaml`.
- An **artifact** contains encrypted `secrets`, readable `inscriptions`, a tomb-local schema reference, and SOPS metadata.
- A **guardian** is a credential-provider-backed native hybrid age identity.
- A **proclamation** is a generated ten-word administrative credential used to sign tomb state and authorize mutations.
- A **seeker** is the current live Tailscale login and/or device tag.
- A **decree** is the signed allow-only reveal policy plus exhaustive artifact and schema locks.

Decree enforcement is advisory for conforming Sphinx use. Credential providers safeguard guardian identities; anyone who independently obtains a guardian identity can use compatible cryptographic tooling outside Sphinx.

## Tomb layout

```text
.tomb/
  tomb.yaml
  decree.yaml
  decree.yaml.sig
  rotations/
    .keep
    00000001.yaml
    00000001.from.sig
    00000001.to.sig
  schemas/
    credential/
      v1.yaml
production/
  api/
    artifact.yaml
```

Managed files are exact regular Git blobs. Sphinx never initializes a repository, stages files, creates commits or tags, signs Git objects, changes branches, pushes, merges, or modifies an immutable cache. Administrative mutations require an explicit caller-managed `path:` worktree.

## Initialize a tomb

Create a Git repository and add at least one schema at `.tomb/schemas/NAME/vN.yaml`; see [docs/SCHEMAS.md](docs/SCHEMAS.md). Then run:

```sh
sphinx decree init --tomb path:/absolute/path/to/tomb
```

Sphinx generates and confirms the proclamation through the controlling terminal and installs the initial default-deny signed metadata transactionally. Commit the resulting files yourself.

Create a proclamation-only artifact interactively:

```sh
sphinx artifact create \
  --tomb path:/absolute/path/to/tomb \
  --schema credential/v1 \
  production/api
```

Add a guardian recipient after creating a provider record:

```sh
sphinx guardian create workstation
sphinx guardian add \
  --tomb path:/absolute/path/to/tomb \
  workstation production/api
```

Commit the encrypted artifact and regenerated decree/signature yourself.

## Sign reveal policy

Edit only `.tomb/decree.yaml` rules and, when needed, tomb-local schemas. Do not stage those edits before signing. Sphinx replaces the editor-visible generation and lock lists:

```sh
sphinx decree sign --tomb path:/absolute/path/to/tomb
```

A seeker matches when either an exact Tailscale login or an exact `tag:` device tag in an allow rule matches. No matching rule means deny.

## Enroll and reveal

From a consuming Git project:

```sh
sphinx tomb add --name default github:example/company-tomb?ref=main
```

Enrollment validates the complete tomb and asks you to approve its proclamation fingerprint. It atomically writes the exact commit, fingerprint, decree generation, timestamp, and guardian selections to `<project-git-root>/.sphinx/config.yaml`.

Configure a matching guardian selection in that project file, then reveal:

```sh
sphinx artifact reveal --tomb default production/api
sphinx artifact reveal --tomb default --secret token production/api
```

All-secret human output is a secrets-only YAML document. A selected value is emitted as one canonical scalar with no added newline. If stdout is a terminal, Sphinx warns and asks for confirmation before writing plaintext. There are no clipboard, output-file, temporary-file, dedicated-descriptor, or child-process output modes.

Readable inscriptions can be inspected without decryption:

```sh
sphinx artifact inspect --tomb default production/api
```

Inspection always warns that inscriptions are unverified until normal authenticated decryption checks the SOPS MAC.

## Update and recovery

```sh
sphinx tomb update default
sphinx tomb validate default
sphinx tomb validate path:/absolute/path/to/tomb
sphinx tomb recover path:/absolute/path/to/tomb --rollback
```

Updates require descendant commits and validate proclamation transitions and monotonic decree generations before changing project locks. Recovery is proclamation-authorized and restores only journaled exact paths when their state still matches a recorded image; it never performs repository-wide Git recovery.

## Guardians and proclamation rotation

The macOS default provider is `apple-icloud-keychain`; `apple-login-keychain` is explicit. `environment` reads one `SPHINX_GUARDIAN` value, captures it once and removes it from the process environment before command parsing, and cannot be mutated.

```sh
sphinx guardian list
sphinx guardian show workstation
sphinx guardian remove --tomb path:/absolute/path/to/tomb workstation --all
sphinx proclamation rotate --tomb path:/absolute/path/to/tomb
```

Removing a recipient does not revoke values revealed previously. Proclamation rotation re-encrypts every artifact with independent fresh data keys and installs a cross-signed trust transition in one transaction.

## Configuration and references

The optional global alias file is `${XDG_CONFIG_HOME:-$HOME/.config}/sphinx/config.yaml` and is manually managed. Sphinx does not mutate it. Project configuration is always `<git-root>/.sphinx/config.yaml`; omitting `--tomb` selects the alias exactly `default`.

Supported tomb references are:

- `github:OWNER/REPOSITORY`
- `git+https://HOST/PATH`
- `git+ssh://HOST/PATH`
- `path:/absolute/worktree`

A reference may have one `?ref=` or `?rev=` selector, never both. References identify repositories only.

## Security and release operations

Before any command body executes, Sphinx sets and verifies the macOS soft and hard core-file size limits as zero. It fails closed if this process control cannot be established. Secrets and proclamation text never enter command arguments; decrypted output still inherits the security of the caller-selected stdout destination.

- [Phase 8 threat-model review](docs/security/THREAT_MODEL_REVIEW.md)
- [Support and interoperability matrix](docs/release/SUPPORT_MATRIX.md)
- [Release procedure](docs/release/RELEASE.md)
- [Transaction recovery](docs/operations/RECOVERY.md)
- [Guardian compromise](docs/operations/GUARDIAN_COMPROMISE.md)
- [Proclamation rotation](docs/operations/PROCLAMATION_ROTATION.md)
- [Rollback guidance](docs/operations/ROLLBACK.md)

Published v0.1.0 checksums, SBOM, and notarization evidence are indexed in [`artifacts/releases/v0.1.0/RELEASE.md`](artifacts/releases/v0.1.0/RELEASE.md).

The production release procedure in `scripts/build-release-macos.sh` requires a Developer ID Application identity and an Apple notarytool Keychain profile. It emits the notarized and stapled disk image, hardened-runtime signing evidence, Gatekeeper result, SHA-256 checksums, and CycloneDX SBOM. `scripts/verify-release-candidate.sh` performs a credential-free ad-hoc candidate build check but does not represent a distributable notarized release.

See [docs/PRD.md](docs/PRD.md), [docs/TERMINOLOGY.md](docs/TERMINOLOGY.md), the [schema guide](docs/SCHEMAS.md), and the [frozen command matrix](docs/redesign/COMMAND_MATRIX.md).
