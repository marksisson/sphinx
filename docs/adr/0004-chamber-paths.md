# ADR 0004: Chamber paths and artifact resolution

- **Status:** Accepted
- **Date:** 2026-08-21

## Context

Artifact paths must be deterministic across Git object reads and macOS worktrees without hiding case distinctions or admitting traversal.

## Decision

A chamber is a non-empty slash-separated ASCII repository path. Every segment matches `[A-Za-z0-9][A-Za-z0-9._-]*`. Absolute paths, empty segments, `.`/`..`, backslashes, percent-encoded separators, any `.git` segment, root `.tomb`, and symlink traversal are rejected. The artifact path is always the exact concatenation `CHAMBER/artifact.yaml`.

Paths are case-sensitive and case-preserving. Git trees containing chambers that differ only by case remain valid; an incapable caller worktree reports a representability error rather than redefining tomb validity. Decree globs are anchored to canonical chamber paths: `*` stays within one segment and a segment exactly `**` spans complete segments.

## Consequences

There is no Unicode normalization, case folding, caller-supplied artifact filename, `dir` selector, or `file` selector. Tests must cover traversal, exact case, symlinks, case collisions, and glob edge cases.
