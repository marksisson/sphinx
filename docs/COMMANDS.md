# Command matrix

All artifact/decree/proclamation mutations require an explicit caller-managed `path:WORKTREE`, a controlling terminal, and proclamation authorization. They never perform Git history or transport operations. Reveal is the only seeker-authorized operation.

| Command | Reads | Mutates | Authorization/output |
|---|---|---|---|
| `tomb add [--name NAME] TARGET` | remote/path tomb, global alias | project config | trust confirmation |
| `tomb update [NAME]` | locked and candidate tombs | project config | descendant/rotation/generation confirmation |
| `tomb status [NAME]` | project config/tomb | none | metadata only |
| `tomb list` | project config | none | metadata only |
| `tomb remove NAME` | project config | project config | confirmation |
| `tomb validate [NAME\|path:WORKTREE]` | tomb | none | named lock: public signed-state validation; explicit path: proclamation-authorized full artifact validation |
| `tomb recover path:WORKTREE --rollback` | transaction journal | exact affected worktree paths | proclamation, deterministic rollback |
| `artifact create --tomb path:WORKTREE --schema SCHEMA CHAMBER` | schema | artifact, decree/signature | proclamation; proclamation-only recipient |
| `artifact set-inscription --tomb path:WORKTREE --inscription NAME CHAMBER` | artifact/schema | artifact, decree/signature | proclamation; fresh data key |
| `artifact reseal --tomb path:WORKTREE [--secret NAME] CHAMBER` | artifact/schema | artifact, decree/signature | proclamation; fresh data key |
| `artifact delete --tomb path:WORKTREE CHAMBER` | artifact/decree | artifact, decree/signature | proclamation |
| `artifact inspect --tomb TOMB CHAMBER` | readable ciphertext fields | none | no identity; conspicuous unverified-MAC warning |
| `artifact reveal --tomb TOMB [--secret NAME] CHAMBER` | locked tomb, tailscaled, guardian | none | seeker decree; plaintext stdout only |
| `artifact validate --tomb TOMB CHAMBER` | artifact/schema/decree | none | full seeker/decree/guardian/recipient/MAC/schema validation; emits no plaintext |
| `guardian create NAME [--provider PROVIDER]` | provider | provider | local generation; writable provider only |
| `guardian show NAME [--provider PROVIDER]` | provider | none | no private key/recipient export |
| `guardian list [--provider PROVIDER]` | provider | none | metadata only |
| `guardian delete NAME [--provider PROVIDER]` | provider | provider | confirmation and reference warning |
| `guardian add --tomb path:WORKTREE [--provider PROVIDER] NAME (CHAMBER... \| --all)` | guardian/artifacts | artifacts, decree/signature | proclamation; fresh key per artifact |
| `guardian remove --tomb path:WORKTREE [--provider PROVIDER] NAME (CHAMBER... \| --all)` | guardian/artifacts | artifacts, decree/signature | proclamation; fresh key per artifact |
| `decree init --tomb path:WORKTREE` | caller schemas | initial `.tomb/` metadata | generated proclamation; no artifacts allowed |
| `decree sign --tomb path:WORKTREE` | caller-edited decree/schemas | decree/signature | proclamation; managed generation/locks |
| `decree validate --tomb TOMB` | locked tomb | none | signature/policy/content validation |
| `decree show --tomb TOMB [--unverified]` | decree | none | verified by default |
| `proclamation rotate --tomb path:WORKTREE` | all tomb state | all artifacts and signed metadata | old plus generated/confirmed new proclamation |

Global flags are `--config`, `--json`, `--quiet`, and `--no-color`. `--json` never disables required controlling-terminal prompts. Decrypted output has no clipboard, file, temporary-file, dedicated-FD, or `exec` mode.
