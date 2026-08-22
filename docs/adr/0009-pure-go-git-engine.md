# ADR 0009: Pure-Go Git engine

- **Status:** Accepted
- **Date:** 2026-08-22

## Context

Sphinx currently delegates repository discovery, immutable materialization, object reads, ancestry, attributes, index inspection, and worktree status to a Git executable found through the runtime environment. That executable is part of the integrity boundary and can inherit behavior that Sphinx must suppress. [`GIT_ENGINE.md`](../GIT_ENGINE.md) inventories the required operations and adversarial compatibility gates.

## Decision

Sphinx will replace every production Git subprocess with `github.com/go-git/go-git/v6` from reviewed main commit `374c354884f12ea0a8f80ae9c429a44a33ba4bb1`, pinned as pseudo-version `v6.0.0-alpha.5.0.20260821142625-374c354884f1`. The build uses Go 1.26 or newer. Native Git remains a pinned differential test oracle and release/source-management tool, never a production fallback.

Only packages below `internal/git` may import go-git. Process startup replaces go-git's global/system configuration plugin with an immutable empty source before any repository opens and freezes that choice. Filesystem storages share an explicitly bounded descriptor pool. Experimental `x/` APIs are part of the reviewed dependency boundary: every go-git commit change requires source review, dependency and license review, the complete differential suite, and release-gate approval.

The accepted repository contract is SHA-1 and SHA-256 object formats; exact loose, packed, or mixed objects; ordinary bare immutable caches; and existing non-bare main or native-Git-created linked worktrees. Sphinx reads index v2 only. Unknown repository extensions, unsupported index versions or extensions, alternates, replacement objects, promisor-dependent missing objects, unsafe linked-worktree metadata, and indeterminate repository interpretation fail closed. Support does not authorize go-git initialization, checkout, index/ref/config writes, authoring, repair, or transport publication APIs.

Transport authentication is deliberately narrower than native Git:

- `github:` and `git+https://` use verified smart HTTPS without credential helpers, `.netrc`, embedded credentials, interactive prompts, or ambient Git configuration. The initial contract is anonymous/public HTTPS.
- `git+ssh://` uses the caller's SSH agent through `SSH_AUTH_SOCK`, mandatory host-key verification against standard user/system known-hosts files, and the user/host/port explicitly represented by the canonical tomb reference (default user `git` when omitted).
- Sphinx does not execute or interpret `ProxyCommand`, `ProxyJump`, credential helpers, identity commands, or arbitrary SSH configuration. Identity files, password authentication, host aliases, custom proxies, and other private-transport mechanisms are unsupported until a superseding ADR defines an in-process secret and routing boundary.
- Redirects never forward credentials across hosts. TLS verification, SSH host verification, cancellation, and secret-free diagnostics are mandatory.

## Consequences

The distributed Sphinx application will no longer require Git or search `PATH`, reducing executable-substitution and ambient-configuration risk while increasing reliance on go-git's repository, pack, protocol, and experimental API parsers. Conservative rejection is acceptable outside the contract; disagreement on accepted repositories is not. No production cutover occurs until every operation has structured differential coverage and the binary succeeds with an empty `PATH`.

Private HTTPS repositories and SSH deployments requiring identity files or routing directives are not supported by the initial pure-Go transport contract. This narrowing must be reflected in the support matrix before transport cutover.
