# Guardian compromise procedure

A guardian holder can decrypt any artifact carrying that guardian recipient outside Sphinx. Decree seeker rules cannot revoke copies already obtained. Treat suspected compromise as exposure of every secret the guardian could unwrap.

1. Preserve current signed tomb state and identify every configured scope containing the guardian fingerprint.
2. From a clean explicit tomb worktree, create a replacement guardian in the intended Apple credential provider:
   ```sh
   sphinx guardian create replacement
   ```
3. Add the replacement recipient to the required tomb scope with `sphinx guardian add`. This requires the proclamation, fully re-encrypts each affected artifact with a fresh data key, updates exhaustive locks, and signs the next decree generation.
4. Remove the compromised recipient with `sphinx guardian remove`. This again uses fresh data keys and an atomic signed mutation.
5. Commit and publish the caller-managed worktree, then advance every consumer with `sphinx tomb update`.
6. Validate each consumer and rotate the actual application credentials stored as secrets. Recipient removal cannot revoke plaintext or old Git blobs already obtained by the compromised holder.
7. Delete the compromised provider record only after no current artifact references it:
   ```sh
   sphinx guardian delete compromised
   ```
8. Review repository and provider access outside Sphinx.

Do not delete the old provider record before recipient removal if it is the only remaining identity capable of an operational reveal. Do not edit SOPS recipients by hand; unsigned or lock-mismatched artifacts are rejected and partial edits can strand recovery.
