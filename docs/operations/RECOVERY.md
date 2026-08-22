# Recovery and rollback procedure

## Interrupted Sphinx mutation

1. Stop all Sphinx operations against the affected worktree.
2. Do not edit managed paths, the journal, Git index, or Git history.
3. Inspect status with `sphinx tomb status path:/absolute/worktree`.
4. Run `sphinx tomb recover path:/absolute/worktree --rollback` from a controlling terminal.
5. Sphinx verifies the journal, guarded dependencies, and exact current target images before restoring only journaled preimages.
6. Run `sphinx tomb validate path:/absolute/worktree` and inspect `git diff --name-only` and `git status --short`.

If the journal is missing, corrupt, or does not match exact pre/post state, Sphinx fails closed. Preserve the worktree and Git administrative directory for investigation. Manually recover only the paths named by trusted repository history; never use a broad reset/restore that could discard unrelated work.

## Complete post-state after a crash

Recovery may recognize that every target already equals the validated postimage. It validates complete signed state and clears the completed journal without rolling back. Do not infer completion from only one modified file.

## Published bad commit

Sphinx does not rewrite history or lower a consuming lock. Create a new descendant commit that repairs the tomb through proclamation-authorized commands, commit it using normal caller workflow, then advance consumers with `sphinx tomb update`. Do not force a consumer back to an older generation.

## Lost guardian

A lost guardian does not require tomb rollback while the proclamation remains available. Follow [guardian compromise](GUARDIAN_COMPROMISE.md) to add a replacement and remove the unavailable recipient. Provider account recovery is controlled by Apple and is not guaranteed by Sphinx.
