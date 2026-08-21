# relic Schemas

A tomb stores versioned, declarative schema definitions below `.sphinx/schemas/`.
Schemas drive secure prompts, validation, help, and shell completion. They never
execute commands or templates and cannot change sphinx's encryption policy or a
decree.

## Definition

```yaml
name: anthropic-api-key
version: 1
description: Anthropic API credential

essence:
  - name: api_key
    type: string
    required: true
    prompt: Anthropic API key

inscription:
  - name: environment
    type: enum
    values: [development, staging, production]
    required: true
    prompt: Environment
  - name: owner
    type: string
    required: true
    prompt: Owning team
```

A schema reference combines its name and version:

```text
anthropic-api-key/v1
```

Supported field types are `string`, `integer`, `boolean`, and `enum`. Field
names are single segments and must be unique across essence and inscription.
Schema changes should use a new version rather than changing the meaning of an
existing version.

## relic format

Each relic is stored at `PATH/relic.yaml`:

```yaml
format: 1
schema: anthropic-api-key/v1
inscription:
  environment: development
  owner: platform
essence:
  api_key: ENC[AES256_GCM,...]
recovery:
  type: passphrase-v1
  encrypted_data_key: <encrypted>
# sphinx-managed public-key wrapping and MAC metadata follows
```

sphinx always encrypts the complete `essence` branch. `format`, `schema`,
`inscription`, and the recovery envelope remain repository-visible but are
covered by the MAC. The sphinx-managed encryption metadata wraps the data key
for the guardian public key; the corresponding private key is stored in macOS
Keychain. The separate recovery envelope wraps the same data key using the
recovery passphrase.

A tomb's `.sphinx/tomb.yaml` binds all relics to the same guardian public key
and recovery passphrase mechanism. It contains an encrypted passphrase check
but never the passphrase.

## Commands

```console
sphinx relic entomb --schema anthropic-api-key/v1 services/anthropic
sphinx relic inspect services/anthropic
sphinx relic inscribe services/anthropic
sphinx relic reseal services/anthropic
sphinx relic reveal services/anthropic --facet api_key
sphinx relic reveal --recovery --tomb ./secrets services/anthropic --facet api_key
```

`entomb` refuses to overwrite an existing relic. `reseal` requires an existing
relic and rotates its data key. Both require the tomb recovery passphrase.
`inscribe` changes only repository-visible metadata and retains the existing
data key and recovery envelope.

essence prompts disable terminal echo. Recovery passphrases are accepted only
from a terminal, never from an argument, environment variable, JSON input, or
standard input.

## Non-interactive values

Automation can supply structured values as JSON while the recovery passphrase
is still read from the terminal:

```console
sphinx relic entomb \
  --schema anthropic-api-key/v1 \
  --from-json ./values.json \
  services/anthropic
```

```json
{
  "essence": {
    "api_key": "sk-ant-example"
  },
  "inscription": {
    "environment": "development",
    "owner": "platform"
  }
}
```

A JSON file contains plaintext essence and must be handled accordingly.
`--stdin` avoids a persistent input file. Neither form accepts the recovery
passphrase.

## Completion

Generate completion for the active shell, for example:

```console
source <(sphinx completion zsh)
```

Completion discovers schema references, existing relic paths, and valid facets
from the selected relic's schema.
