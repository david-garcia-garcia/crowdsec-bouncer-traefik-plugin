## Why

`plugin.go` `openOwnedLeg` still picks `lapi.OpenStream` or `lapi.OpenLive` from `LapiMode`. Both functions already do the same reclaim Open; `noteStreamOwner` already no-ops unless mode is stream or alone. AppSec and captcha already expose one `Open`. The leftover consumer split is not a constructor concern.

## What Changes

- Replace `OpenStream` and `OpenLive` with one exported `lapi.Open` (`ctx, cfg, log, middlewareName, pluginVersion`), same signature as `appsec.Open` / `captcha.Open`.
- Remove `OpenStream` and `OpenLive`. Do not keep aliases.
- Body is today’s shared reclaim Open (DecisionStore, `OwnershipKey`, `New`, hooks, `bindIdentity`) plus `noteStreamOwner`. Live/none still return before the collision index.
- `plugin.go` LAPI case becomes one `lapi.Open` call. It does not read `LapiMode` to pick an entry point.
- Retarget the 54 Go consumer calls (2 in `plugin.go`, 52 in `pkg/lapi` tests). Test function names that mention OpenStream or OpenLive may stay as scenario labels. No test-only alias.
- Fold the two live catalog leaves that still name `OpenStream` / `OpenLive` as current contract. No new spec family.
- Do not change stream, live, none, or alone runtime, collision warn text, AppSec or captcha `Open`, identity owners, or public config keys.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_lapi_connection`: callers import `Open` instead of `OpenStream` / `OpenLive`; `AdoptTransport` runs after `Open` bind.
- `core_plugin_decisionstore_store`: DecisionStore Open uses the same Traefik `New` context as `lapi.Open`.

## Impact

- `plugin.go` — `openOwnedLeg` LAPI branch becomes one `lapi.Open`.
- `pkg/lapi/session.go` — one `Open`; drop `OpenStream` / `OpenLive`; `noteStreamOwner` stays inside `Open`.
- `pkg/lapi/zzz_*.go` — 52 call sites retarget to `Open`.
- Live catalog deltas in this change folder. Usage packets move with implement / `opd-devdocsimpact`.
- No operator YAML names these symbols. No public config keys change.
