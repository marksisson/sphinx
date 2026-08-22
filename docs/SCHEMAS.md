# Tomb schemas and artifacts

Schemas are immutable-per-artifact, tomb-local definitions. A reference `name/vN` resolves only to `.tomb/schemas/name/vN.yaml` in the same exact Git commit as the artifact.

## Strict YAML

Every schema and artifact must be UTF-8 without BOM, use LF line endings, and end with exactly one LF. Sphinx rejects unknown fields, duplicate mapping keys, anchors, aliases, custom tags, merge keys, non-string mapping keys, and multiple documents.

## Schema path and identity

A schema named `credential` at version `1` is stored exactly at:

```text
.tomb/schemas/credential/v1.yaml
```

Its contents identify the same reference:

```yaml
version: 1
name: credential
description: API credential with operational metadata
secrets:
  - name: token
    type: string
    required: true
    prompt: Token
  - name: enabled
    type: boolean
    required: true
    prompt: Enabled
inscriptions:
  - name: owner
    type: string
    required: true
    prompt: Owning team
  - name: environment
    type: enum
    required: true
    prompt: Environment
    values:
      - development
      - staging
      - production
```

Schema names match lowercase `[a-z][a-z0-9-]*`. Versions are positive integers encoded as `vN` in the path/reference. Field names match `[A-Za-z_][A-Za-z0-9_]*` and must be unique across both containers.

## Field grammar

Every field requires:

- `name`
- `type`
- `required`
- non-empty `prompt`

Supported types are:

| Type | Artifact value |
|---|---|
| `string` | YAML string |
| `integer` | YAML integer |
| `boolean` | YAML boolean |
| `enum` | YAML string exactly equal to one unique `values` entry |

Only enum fields may contain `values`, and an enum requires at least one value. Values are not coerced. Null, floating-point, timestamp, binary, mapping, and sequence values are rejected.

A required field must exist. A required string or enum cannot be empty because SOPS does not produce an encrypted scalar for an empty string. Optional omitted fields are absent rather than null.

## Artifact shape

An artifact is always `CHAMBER/artifact.yaml`. Its decrypted domain shape is:

```yaml
format: 1
schema: credential/v1
secrets:
  token: example-value
  enabled: true
inscriptions:
  owner: platform
  environment: production
```

The stored document includes a SOPS mapping. Only the complete top-level `secrets` mapping is encrypted, using exact `encrypted_regex: ^secrets$`. `inscriptions` remain readable for inspection but are not trusted until authenticated decryption verifies the normal SOPS MAC.

Every stored artifact has exactly one proclamation recipient and zero or more unique native hybrid guardian recipients. Sphinx rejects unsupported recipient types, groups, thresholds, duplicates, malformed armor, and non-native stanzas.

An artifact’s schema reference cannot be changed after creation. Create a replacement artifact if a different schema is needed.

## Authoring lifecycle

Create a schema before initializing tomb metadata:

```sh
mkdir -p .tomb/schemas/credential
$EDITOR .tomb/schemas/credential/v1.yaml
sphinx decree init --tomb path:/absolute/path/to/tomb
```

Create an artifact interactively:

```sh
sphinx artifact create \
  --tomb path:/absolute/path/to/tomb \
  --schema credential/v1 \
  production/api
```

Sphinx reads values only through the controlling terminal. It validates the schema before encryption, creates a proclamation-only artifact with a fresh data key, and atomically updates the signed exhaustive locks.

Update one readable value:

```sh
sphinx artifact set-inscription \
  --tomb path:/absolute/path/to/tomb \
  --inscription owner \
  production/api
```

Replace all secrets or one named secret:

```sh
sphinx artifact reseal --tomb path:/absolute/path/to/tomb production/api
sphinx artifact reseal \
  --tomb path:/absolute/path/to/tomb \
  --secret token \
  production/api
```

Each inscription update and reseal generates a fresh independent data key and re-encrypts every secret. Guardian recipient changes do the same for each selected artifact.

Delete only through the signed transaction boundary:

```sh
sphinx artifact delete --tomb path:/absolute/path/to/tomb production/api
```

Sphinx asks for confirmation and proclamation authorization, deletes the exact artifact path, and regenerates decree locks/signature atomically.

## Validation and inspection

```sh
sphinx tomb validate path:/absolute/path/to/tomb
sphinx artifact validate --tomb default production/api
sphinx artifact inspect --tomb default production/api
```

Worktree tomb validation requires the proclamation and authenticates every artifact against its schema. Artifact validation on an enrolled tomb performs live seeker authorization and guardian decryption but emits no secret values. Inspection performs no decryption and always warns that readable inscriptions are unverified.

## Schema changes

An existing artifact pins its schema reference, while the decree pins exact schema bytes. Editing a referenced schema therefore requires proclamation-authorized `decree sign` and must leave every locked artifact valid under that schema:

```sh
$EDITOR .tomb/schemas/credential/v1.yaml
sphinx decree sign --tomb path:/absolute/path/to/tomb
```

Editable decree/schema paths must be unstaged. Sphinx snapshots and guards them but never modifies the Git index. If a change would invalidate any artifact, signing fails without installing signed state.
