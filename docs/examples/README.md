# Configuration and format examples

Strict initial-format examples used by documentation and release checks:

- [`schema.yaml`](schema.yaml) — tomb-local artifact schema
- [`decree.yaml`](decree.yaml) — signed allow-only reveal policy before its detached signature
- [`project-config.yaml`](project-config.yaml) — consuming-project tomb lock at `.sphinx/config.yaml`
- [`global-config.yaml`](global-config.yaml) — optional manually managed global tomb aliases

These files are parsed through the production decoders by `internal/release/check`.
