# Proclamation rotation procedure

Rotation requires the current proclamation, a clean explicit local tomb worktree, access to every locked artifact/schema/rotation blob, and enough time to complete one all-artifact transaction.

1. Ensure no Sphinx transaction is pending and all managed paths are clean.
2. Validate current state:
   ```sh
   sphinx tomb validate path:/absolute/worktree
   ```
3. Run:
   ```sh
   sphinx proclamation rotate --tomb path:/absolute/worktree
   ```
4. Enter the current generated phrase at the controlling terminal. Record the newly generated ten-word phrase using an owner-approved offline procedure; Sphinx provides no export or backup file.
5. Sphinx derives independent new keys and salt, re-encrypts every artifact with fresh data keys, creates the next manifest and decree generation, and appends a transition signed by both old and new proclamation identities. Any failure rolls back the exact journaled paths.
6. Validate the worktree again, inspect the exact Git diff, then commit and publish through normal caller-managed Git workflow.
7. Advance every consuming project with `sphinx tomb update` and validate it. Until consumers advance, they remain pinned to the old commit and proclamation fingerprint.
8. Test an authorized reveal through each required guardian provider.

Never perform a partial/manual recipient replacement, delete transition blobs, reuse a tomb salt, add a second proclamation recipient, or force consuming configuration backward. If interrupted, use the exact [recovery procedure](RECOVERY.md).
