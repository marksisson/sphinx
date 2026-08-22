# Phase 6 implementation record

Phase 6 replaces the user-facing command surface with the synchronous CLI defined by the frozen command matrix. No command starts or contacts a Sphinx service. Phase 7 removes the now-unreachable superseded packages and rewrites the remaining legacy documentation/release metadata.

## Final command tree

`cmd/sphinx` now exposes only:

- `tomb add|update|status|list|remove|validate|recover`
- `artifact create|set-inscription|reseal|delete|inspect|reveal|validate`
- `guardian create|show|list|delete|add|remove`
- `decree init|sign|validate|show`
- `proclamation rotate`
- `completion`

The previous artifact vocabulary, online reveal flags, recovery bypass, service endpoint flag, and `tomb protect` entry point were deleted from the executable. Root help contains no service lifecycle. Global flags are exactly `--config`, `--json`, `--quiet`, and `--no-color`; command-specific flags follow `docs/redesign/COMMAND_MATRIX.md`. There are no clipboard, output-file, explicit-FD, `exec`, piped authoring, or caller-supplied secret-file modes.

All mutation commands require an explicit `path:` worktree. They call the Phase 4/5 transaction and signed-state boundaries and never invoke Git history/index/transport operations. Tomb enrollment/update remain separate project-config operations.

## Tomb and project commands

- `tomb add` resolves a direct reference or manually maintained global alias, materializes and validates the exact commit, derives the initial lock only from verified signed state, displays the proclamation fingerprint through the controlling terminal, requires explicit trust, and atomically adds one project entry.
- `tomb update` prepares every selected candidate before prompting, enforces descendant-only signed trust advancement and monotonic generations, and installs all accepted lock changes in one stale-checked project-config replacement. No argument updates every mutable project tomb.
- Status/list return only lock metadata. Remove confirms and deletes only the project entry.
- Locked validation checks external fingerprint pinning, transitions, generation, decree, all schemas, and all artifact structure/locks. Explicit worktree validation additionally verifies the proclamation and decrypts/MAC/schema-validates every artifact.
- Recovery obtains the exact pre-operation manifest from the journal, or the post-operation manifest for interrupted initialization, verifies the applicable proclamation, restores only journaled paths, and validates either the signed pre-state or the no-metadata initialization pre-state. A committed initialization journal validates the complete post-state before cleanup.

## Administrative authoring

`decree init` is the only metadata initializer. It requires an existing Git worktree with at least one canonical schema and no artifacts, generates/confirms a ten-word proclamation through the controlling terminal, creates a random UUIDv4 tomb ID and salt, and transactionally installs `tomb.yaml`, a generation-1 default-deny signed decree, detached signature, and zero-byte `rotations/.keep`. It does not initialize or modify Git history/index state.

`decree sign` authenticates the committed current signed state, verifies the prompted proclamation, accepts only an unstaged caller-edited decree and schemas, forbids manifest/artifact/rotation edits, replaces managed generation and exhaustive lock fields, increments once, signs exact bytes, and transactionally replaces only decree/signature while snapshot-guarding every input. Staged editable inputs are rejected so Sphinx never creates ambiguous index/worktree state.

Artifact create, inscription update, reseal, and delete:

- require controlling-terminal authoring and proclamation authorization;
- resolve schema and current state from the committed worktree revision;
- prepare valid encrypted post-images before transaction entry;
- regenerate exhaustive locks and detached signature through authenticated `MutationBuilder`;
- preserve existing non-executable modes;
- increment generation exactly once;
- rotate the SOPS data key for inscription/reseal mutations;
- never accept stdin, argv, environment, or input-file secret values.

Creation installs a proclamation-only artifact and emits stable `guardian_required` warning metadata. Deletion confirms before proclamation access. Guardian add/remove resolve provider-authoritative records, require explicit scope or `--all`, retain deterministic scope ordering, and fully re-encrypt each selected artifact under an independent fresh key in one signed transaction.

Guardian create/show/list/delete expose only non-secret record metadata. Show/list omit both private identity and public recipient export. Read-only environment mutation still fails at the provider boundary. Delete requires confirmation and warns that artifacts may retain the recipient.

Proclamation rotation obtains the old proclamation, generates/confirms the replacement, and invokes the Phase 5 complete all-artifact cross-signed rotation transaction.

## Synchronous inspect, reveal, and validate

Inspect resolves immutable committed content, verifies externally pinned signed state for enrolled tombs, performs no decryption or identity lookup, emits only schema/inscriptions/recipient fingerprints, marks `verified: false`, and always emits stable warning `unverified_inscriptions` even under `--quiet`.

Reveal resolves exactly one chamber through the project lock and invokes `reveal.Coordinator`: pinned commit/signatures/locks/generation, fresh tailscaled LocalAPI state, allow-only seeker policy, configured guardian order/intersection, SOPS MAC, and schema must all pass. The CLI then owns only output policy:

- all-secret human output is a secrets-only YAML document in schema order;
- selected string/enum output is exact UTF-8 bytes, selected integers are canonical base-10, and booleans are lowercase, with no added newline;
- JSON places plaintext only under `data.secrets`;
- plaintext is written only to stdout;
- if stdout is a terminal, a conspicuous stderr warning and controlling-terminal confirmation occur before any plaintext write;
- redirected/piped stdout requires no additional confirmation;
- diagnostics and errors contain no plaintext values.

Artifact validate uses the same live seeker/guardian/MAC/schema flow but destroys the decrypted document without emitting secret data.

## Stable result contract

`internal/cliresult` defines version-1 deterministic single-object envelopes and the fixed BSD `sysexits` subset. Except completion, command success in JSON mode writes exactly one newline-terminated object to stdout. Failure leaves stdout empty and writes exactly one error object to stderr. Stable codes include all documented registry values, with dedicated handling for usage, malformed data, integrity, missing input, Tailscale/dependency availability, proclamation/guardian/authorization denial, worktree/recovery conflicts, create/I/O failure, configuration, and internal invariants. No intentional handled path exits `1`.

Prompts always use the controlling terminal and therefore never corrupt stdout/stderr JSON streams. Required warnings are represented as ordered `{code,message}` objects. Human `--quiet` suppresses ordinary success text but not security warnings or decrypted output explicitly requested by reveal. `--no-color` is accepted and all current output is color-free.

## Worktree and recovery hardening added in Phase 6

- `GuardMutationInputs` snapshots explicitly caller-edited decree/schema inputs while rejecting staged versions and retaining all attribute, symlink, Git-operation, and TOCTOU checks.
- Ordinary signed mutation dependencies now include every existing immutable rotation blob in addition to manifest, artifacts, and schemas.
- `LoadWorktreeContent` reconstructs complete canonical managed state without consulting the index and rejects alternate `.tomb/` metadata.
- Journal APIs expose authenticated exact pre/post manifest images for recovery authorization without broad filesystem or Git recovery.
- Initialization recovery supports both incomplete rollback and committed-journal cleanup while requiring a valid schema-only pre-state or valid complete post-state respectively.

## Tests and gate

`cmd/sphinx/cli_test.go` treats the root command as a black-box interface over temporary real Git repositories. It verifies the exact final command tree, absence of retired commands and forbidden I/O flags, JSON usage/sysexits behavior, missing-terminal authoring rejection, unsupported stdin rejection, terminal reveal decline/approval without leakage, successful stdout-only JSON reveal, secret-free validate output, fresh fake tailscaled LocalAPI calls, and fail-closed unavailable LocalAPI errors. The reveal fixture uses real strict tomb/config files, native hybrid SOPS recipients, detached decree signatures, exhaustive locks, immutable materialization, and a provider-authoritative fake guardian.

Additional tests cover initialization/default-deny signing, strict worktree state loading, unsupported metadata rejection, editable-input staging rejection, exact JSON envelopes, and stable error mappings.

`scripts/verify-phase6.sh` runs command/domain tests and race tests, builds the executable, asserts executable-level exit 64 plus exact JSON for the removed `--server` flag, checks the root help tree, and scans production CLI code for network-service/client identity paths and forbidden input/output modes.
