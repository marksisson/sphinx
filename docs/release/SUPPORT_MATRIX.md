# Initial-release support and interoperability matrix

## Supported runtime

| Boundary | Initial release |
|---|---|
| Operating system | macOS |
| Architecture | Apple Silicon (`darwin/arm64`) |
| Build toolchain | Go 1.26.5 |
| Production Git engine | reviewed in-process go-git commit; no Git executable or runtime fallback |
| Differential Git oracle | Git 2.55.0 from the locked development/verification environment only |
| Credential providers | `apple-icloud-keychain` (default), `apple-login-keychain`, read-only `environment` |
| Identity source | fresh authenticated tailscaled LocalAPI status per reveal |
| Repository | non-bare Git repository; exact regular blobs |
| Tomb references | `github:`, `git+https://`, `git+ssh://`, explicit `path:` |
| HTTPS Git transport | anonymous public smart HTTPS; system TLS roots; initial-request redirects only; no ambient proxy |
| SSH Git transport | explicit URL host/user/port; `SSH_AUTH_SOCK`; standard user/system known-host files |
| Unsupported Git authentication | HTTPS credentials/helpers/`.netrc`; SSH passwords, identity files, host aliases, proxy/command directives |
| Artifact format | `format: 1`, strict YAML, native hybrid SOPS |
| Decree/schema/config formats | version 1 only |
| Output | stdout only; version-1 JSON envelope when requested |

Intel macOS, Linux, Windows, plaintext HTTP Git transport, dumb HTTP Git transport, private HTTPS authentication, SSH without an agent and verified known-host entry, ambient Git/SSH/proxy routing, background operation, offline reveal, alternate output sinks, migration readers, and old formats are unsupported.

## Cryptographic interoperability

| Component | Pinned implementation | Accepted suite |
|---|---|---|
| age | `filippo.io/age` v1.3.1 | native ML-KEM-768 + X25519 hybrid |
| SOPS | `github.com/getsops/sops/v3` v3.12.1 | one key group, native hybrid age recipients, AES-256-GCM tree encryption and MAC |
| signatures | Go Ed25519 + CIRCL v1.6.3 | Ed25519 and FIPS 204 ML-DSA-65 both required |
| proclamation derivation | `golang.org/x/crypto` | fixed `argon2id-v1` plus domain-separated HKDF |

Runtime invokes no age/SOPS executable or plugin. External pinned tools are interoperability oracles in tests only. Classical-only age, plugin, KMS, PGP, SSH, threshold/Shamir, duplicate, and multiple-proclamation recipient encodings are rejected.

## Release acceptance

A distributable disk image is acceptable only when the complete verification gate passes, the binary is arm64 PIE, both soft/hard core-size limits are established as zero before command execution, the hardened-runtime Developer ID signature verifies, Apple notarization succeeds, its ticket is stapled and validated on the disk image, Gatekeeper accepts that distributable image, disk-image and binary SHA-256 checksums are published, and the CycloneDX SBOM corresponds to that binary's embedded Go module build information.
