# ADR 0008: Decree trust bootstrap and rotation

- **Status:** Accepted
- **Date:** 2026-08-21

## Context

A decree signature cannot bootstrap trust from a verification key stored only beside attacker-replaceable repository content. Valid older signed tomb states must also be prevented from replay in descendant commits.

## Decision

Enrollment explicitly approves and externally pins the proclamation signing-bundle fingerprint with the exact Git commit and signed decree generation. A decree signature binds exact decree bytes, exact `tomb.yaml` SHA-256, format version, tomb UUID, and purpose `sphinx decree`. The signed decree contains exhaustive bytewise-sorted artifact and schema SHA-256 locks.

Every authorized signed-state mutation increments a uint64 decree generation exactly once. Update requires a descendant commit and rejects lower generations or same-generation signed-state changes. Proclamation rotation creates a contiguous append-only transition cross-signed by old and new bundles under distinct `/from` and `/to` purposes, re-encrypts every artifact, and atomically changes manifest, decree, locks, signatures, and transition files. Consumers advance commit, fingerprint, and generation only after validating the whole candidate.

## Consequences

Initial enrollment is explicit TOFU or out-of-band verification. Replacing the manifest and decree together, replaying an older valid state, truncating/reordering rotations, or presenting a singly signed transition fails closed. Generic suite rotation remains unsupported until a superseding bridge ADR exists.
