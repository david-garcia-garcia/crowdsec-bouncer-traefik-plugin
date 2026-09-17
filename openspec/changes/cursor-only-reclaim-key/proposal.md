## Why

On DestBranch, stream (and live/none) reclaim still keys by a first-wins settings hash, so two routers that share one CrowdSec cursor row but disagree on intervals, CAPI scenarios, `updateMaxFailure`, or `decisionScopeHeaders` warn-and-wire into a sibling slot. `scopes=` is first-wins on that same key. Peek exists only for that path. `pkg/reclaim` is still a local table fork.

## What Changes

- Stream Open key becomes cursor + Redis (`lapi:stream:` + SessionHex + `storeParams` hash). Live/none Open key drops the same remaining fields (`lapi:` + SessionHex + same Redis hash). Distinct table prefixes stay (`lapi:stream:`, `lapi:`, `decisionstore:`, `appsec:`).
- Delete `Peek`, `PeekLivePrefix`, and `View`. After one cursor+Redis key, `Open` of that key Wakes the sleeper. No replacement inspect API. Interval / CAPI / `updateMaxFailure` mismatch on a live sibling is silent first-wins.
- Requested `scopes=` and the store header-scope filter read a Client-owned live-router union. Leave write-once `decisionScopeHeaders` as first-create residue. No auto-`startup=true` when the union grows. No sweep when it shrinks.
- Import utilities `reclaim` v1.0.3 and delete the local `table.go` fork. Keep the local shim only (`Default`, `ProcessGrace` 30s, `Open` / `OpenWithHooks`, `ResetForTest` / `ResetForTestWith`). Do not take `OpenTyped` (it does not remove hooks-as-funcs). AppSec stays on `OpenWithHooks` + type assert; AppSec reclaim key is unchanged.
- Document upgrade: SessionHex and store Redis params stay; existing Redis keys stay reachable; only the in-process Client Open string changes. Implement deletes `knowledge/debt/2026-09-17-cursor-only-reclaim-key.md`.
- Not **BREAKING** for operators. Public Traefik config keys stay. Redis key prefix stays `SessionHex`.

## Capabilities

### New Capabilities

- `core_plugin_lapi_scope-union`: Client-owned live-router header-scope union for LAPI `scopes=` and the stream store filter. Register after a successful stream bind; drop on constructor ctx Done. Miss window when the union grows; no sweep when it shrinks.

### Modified Capabilities

- `core_plugin_lapi_reclaim-key`: Client Open key is cursor + Redis, not first-wins settings hash. No `PeekLivePrefix` / warn-and-wire. Sleeping interval/CAPI/scopes change Wakes the same slot; sleeping Redis-host change stays a new key.
- `std_go_reclaim_context-lease`: Import utilities `reclaim`; delete Peek / View; keep the local shim. Hooks stay function values. Do not take `OpenTyped`.
- `core_cache_client_decision-store`: First-wins `scopes=` and warn-and-wire no longer stay on the Client key. Store filter follows the Client union. Store key and SessionHex prefix stay.
- `core_plugin_decisions_scopes`: Stream `scopes=` is the live-router union, not the first constructor’s map. CAPI still omits `scopes=`. Live/none still pass scopes per `LiveLookup`.

## Impact

- `pkg/lapi/session.go`, `identity.go`, `client.go`, `client_decisions.go`, session/plugin tests
- `pkg/reclaim` (delete `table.go` / `peek.go`; shim imports utilities)
- `pkg/appsec/session.go` only for the reclaim import and hooks / `OpenTyped` (leave workaround)
- `openspec/specs/core_plugin_lapi_reclaim-key/`, `std_go_reclaim_context-lease/`, `core_cache_client_decision-store/`, `core_plugin_decisions_scopes/`, plus new `core_plugin_lapi_scope-union/`
- Usage packets still describe DestBranch; implement / `sbs-dev-devdocsimpact` update them after apply
- `knowledge/debt/2026-09-17-cursor-only-reclaim-key.md` (delete on implement)
- No `pkg/captcha/`, no AppSec key-shape change, no utilities or `vendor/` edit, no `atomic.Pointer[T]`, no union of intervals / Redis / CAPI scenarios / `updateMaxFailure`
