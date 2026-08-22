# ADR 0001: Local policy threat model

- **Status:** Accepted
- **Date:** 2026-08-21

## Context

The discarded MVP coupled reveal to an HTTP server, daemon lifecycle, and local audit subsystem. A guardian identity holder can invoke age/SOPS outside Sphinx, so CLI policy cannot be represented as DRM.

## Decision

Sphinx is a synchronous local CLI with no server, listener, LaunchAgent, client protocol, persistent identity cache, or local audit log. Every reveal obtains a fresh seeker from tailscaled LocalAPI, verifies the externally pinned decree trust chain and exact committed artifact, applies allow-only policy, finds a configured guardian recipient, decrypts, verifies the SOPS MAC and schema, and writes plaintext only to stdout.

Decree enforcement is advisory for conforming Sphinx use. Credential providers protect guardian identities; proclamation-signed exhaustive locks make unauthorized tomb-content changes detectable. A guardian holder can bypass policy using compatible tools, and documentation must say so.

## Consequences

- Missing or unusable tailscaled state fails closed; there is no offline mode, override, grace period, or identity cache.
- Login and `tag:` seeker identities match independently with OR semantics.
- `runProtect`, HTTP, LaunchAgent, chronicle, and daemon configuration are deleted rather than adapted.
- This ADR can change only with a new product threat model and explicit owner approval.
