## Why

Traefik Yaegi stores the `CreateConfig` pointer and `New` currently mutates that same `*configuration.Config` (log level, deprecated path aliases, CAPI rewrite, secret file inlining) before `IdentityHex`. The host’s live Config is a scratchpad; identity hashes rewritten fields. Operators and later `New` calls on that pointer do not see the decoded DTO.

## What Changes

- `New` copies Traefik’s Config, then applies log-level normalize, deprecated path aliases, `ValidateParams`, and `Prepare` on the copy only.
- `IdentityHex` / `Key`, `crowdsecconnection.New`, and `bouncer.New` use that prepared snapshot.
- Traefik’s original Config pointer is not assigned (LogLevel, Ban/Captcha paths, LAPI/AppSec/Redis keys, CAPI host/path/scheme stay as decoded).
- CAPI alone-mode rewrite and secret file loading behavior stay the same on the snapshot.
- Tests that inspect Config after `New` assert the caller pointer is unchanged and use the snapshot for prepared values.

No **BREAKING** public JSON config keys.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_instance-reclaim`: `New` prepares a Config snapshot for reclaim identity and construction; Traefik’s CreateConfig pointer is not mutated.

## Impact

- `plugin.go` `New` (copy before mutate).
- `pkg/crowdsecconnection.Prepare` still mutates its argument (the snapshot).
- `pkg/bouncer.New` captcha file loads still write the snapshot, not Traefik’s pointer.
- Tests in `plugin_test.go` (and any New caller that re-reads Config).
- Usage packet `knowledge/devdocs/core_plugin_middleware.md` after apply.
