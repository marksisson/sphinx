# Release and signed-state rollback guidance

## Executable rollback

A previously notarized Sphinx executable may be restored only when its supported format and cryptographic suite are identical to current tomb state and the release advisory does not prohibit it. Verify the archived SHA-256 checksum, code signature, notarization assessment, architecture, and SBOM before replacement. Never substitute an unsigned binary under the same version.

Executable rollback does not authorize tomb-state rollback. A prior executable that cannot validate the current initial format, rotation chain, or security controls must fail closed and must not be used.

## Tomb state

Do not move a consuming lock, decree generation, or proclamation fingerprint backward. Repair errors with a new proclamation-authorized descendant commit and the next generation. Existing cross-signed rotation records are immutable.

For an uncommitted interrupted mutation, use only `sphinx tomb recover path:/absolute/worktree --rollback`; it restores exact journaled preimages after validation. For committed errors, follow the new-descendant procedure in [RECOVERY.md](RECOVERY.md).

## Guardian or proclamation compromise

Executable rollback does not revoke recipient identities. Follow [guardian compromise](GUARDIAN_COMPROMISE.md) or [proclamation rotation](PROCLAMATION_ROTATION.md), rotate underlying application credentials where exposure is possible, and advance all consumers.
