# ADR 0003: Tomb-reference grammar

- **Status:** Accepted
- **Date:** 2026-08-21

## Context

The previous locator admitted directory/file selectors and conflated repository materialization with artifact selection.

## Decision

A tomb reference identifies one Git repository and has at most one selector: `?ref=` for a mutable branch/tag or `?rev=` for a full immutable commit. Selectors are mutually exclusive. Supported forms are `github:OWNER/REPOSITORY`, `git+https://…`, `git+ssh://…`, and `path:WORKTREE`. References never contain a chamber or artifact filename.

Unknown or repeated query keys, fragments, embedded credentials, generic HTTP resources, archives, unsafe ref names, and non-Git path targets are rejected. Relative `path:` values resolve from the current directory without symlink traversal and must resolve to the worktree root. Canonical references are used for duplicate detection and project-lock lookup.

## Consequences

- Chamber selection is always a separate argument.
- Global aliases are manually managed enrollment conveniences, not locks.
- Omitted `--tomb` selects the project alias exactly `default`; no single-entry fallback exists.
