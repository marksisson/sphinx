# ADR 0002: Canonical tomb repository layout

- **Status:** Accepted
- **Date:** 2026-08-21

## Context

The old `.sphinx/` tomb metadata and mutable local settings mixed producer and consumer concerns, and Git cannot represent an empty directory.

## Decision

A tomb is a Git repository. Tomb metadata exists only at `.tomb/tomb.yaml`, `.tomb/decree.yaml`, `.tomb/decree.yaml.sig`, `.tomb/rotations/`, and `.tomb/schemas/`. An unrotated tomb commits a required zero-byte `.tomb/rotations/.keep`; transition records use contiguous eight-digit sequence filenames. Consuming-project configuration exists only at `<git-root>/.sphinx/config.yaml`.

Artifacts are exact regular Git blobs at `CHAMBER/artifact.yaml`. Schemas are exact regular blobs at `.tomb/schemas/NAME/vN.yaml`. Validation reads locked blobs from the Git object database and rejects submodules, symlinks, LFS pointers, filters, working-tree encodings, and line-ending transformations on managed paths.

## Consequences

- `.tomb/` and `.sphinx/` are not aliases and have no migration readers.
- Tomb locks bind exact commits, proclamation fingerprints, and decree generations.
- Sphinx edits only explicit caller-managed `path:` worktrees and never stages, commits, signs Git objects, pushes, branches, merges, initializes repositories, or mutates caches.
