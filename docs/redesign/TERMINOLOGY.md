# Frozen redesign terminology

This Phase 0 mapping is normative for package names, CLI help, formats, documentation, tests, and errors.

| Canonical term | Meaning | Retired MVP terms replaced |
|---|---|---|
| Sphinx | Local CLI | client, service |
| Tomb | Git repository of encrypted artifacts and `.tomb/` metadata | named remote settings |
| Chamber | Exact case-sensitive repository path containing `artifact.yaml` | directory selector |
| Artifact | One schema-conforming SOPS document | relic |
| Secret | Encrypted top-level scalar artifact value | essence |
| Inscription | Readable top-level scalar covered by the SOPS MAC | facet |
| Schema | Tomb-local `name/vN` definition | external schema locator |
| Guardian | Credential-provider-backed native hybrid age identity | recovery key, envoy |
| Proclamation | Generated ten-word administrative credential | recovery incantation |
| Seeker | Current live Tailscale login and/or device tag | petitioner, explorer |
| Decree | Signed allow-only reveal policy and exhaustive locks | riddle, petition |

The following are forbidden in new interfaces or persisted formats: `relic`, `essence`, `facet`, `recovery key`, `recovery incantation`, `explorer`, `envoy`, `petition`, `petitioner`, `riddle`, `temple`, `medjay`, and server-sense `protect`/`daemon`.

Low-level cryptographic terms such as recipient, identity, data key, ciphertext, KEM, MAC, and SOPS metadata retain their conventional meanings.
