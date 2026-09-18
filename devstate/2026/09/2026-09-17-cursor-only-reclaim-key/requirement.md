# Requirement
IssueKey: 2026-09-17-cursor-only-reclaim-key

## Problem
Last step of the five-change series. Stream reclaim still keys by session prefix plus a first-wins settings hash, so routers that share one CrowdSec cursor row warn-and-wire into a sibling slot. `scopes=` is first-wins. `Peek` / `PeekLivePrefix` / `View` exist only for that path. `pkg/reclaim` is still a local table fork; `pkg/cache` already imports upstream `simpleredis`.

## Current (code)
- CrowdSec stream cursor is the bouncer row for hashed `X-Api-Key` plus LAPI-visible outbound IP, not plugin settings. `knowledge/research/ext_crowdsec_lapi_stream-cursor/notes.md`
- Stream/alone Open key is `SessionPrefix` + `hashJSON(settingsFrom)` (`SessionKey`). Settings include intervals, Redis, `updateMaxFailure`, CAPI scenarios, `decisionScopeHeaders`. `pkg/lapi/session.go`
- Live/none Open key is `lapi:` + `IdentityHex` (`identity` includes the same remaining knobs except `decisionScopeHeaders`). `pkg/lapi/identity.go`
- DecisionStore key is `decisionstore:` + `SessionHex` + Redis-params hash. Cache prefix is `SessionHex` for every mode. `pkg/lapi/decisionstore.go`
- `CachePrefix` is not found. `#66` removed it; live Redis is no longer `IdentityHex`.
- `OpenStream` uses `PeekLivePrefix(SessionPrefix)` to warn-and-wire a live sibling, then `Peek(bindKey)` to retitle a sleeper with `Holders == 0`. `pkg/lapi/session.go`
- `streamQuery` appends `&scopes=` from `c.decisionScopeHeaders` (first constructor). CAPI omits it. `pkg/lapi/client_decisions.go`
- `storeStreamDecision` drops header scopes not in that same map. `pkg/lapi/client_decisions.go`
- `decisionScopeHeaders` is a write-once `Client` field set in `New`. `pkg/lapi/client.go`
- `Peek` / `PeekLivePrefix` / `View` live in `pkg/reclaim/peek.go` and `pkg/reclaim/default.go`. Production: `pkg/lapi/session.go`. Tests: `pkg/lapi/zzz_session_test.go`, `pkg/reclaim/zzz_peek_test.go`, also `zzz_plugin_test.go`.
- Peek Yaegi notes: one `View` struct (4-value return), key-only map range. `pkg/reclaim/peek.go`
- Local `pkg/reclaim/table.go` matches utilities `v1.0.3` (`950b08d`) except CRLF. AfterFunc grace (Yaegi `_select` hang) is in both. Upstream has `New`, `Table`, `Open`, `OpenWithHooks`, `OpenTyped`, no Peek. `D:/repositories/traefik-middleware-utilities/reclaim/`
- `OpenTyped[T]` wraps `OpenWithHooks` and asserts `T`. Create still returns `(any, Hooks, error)`. `reclaim/opentyped.go`
- Hooks-as-funcs: `clientHooks` in `pkg/lapi/session.go`; AppSec inlines the same. Comment: Yaegi panics asserting a foreign concrete type.
- Shim already: `Default()`, `ProcessGrace = 30s`, `Open` / `OpenWithHooks`, `ResetForTest` / `ResetForTestWith`. `pkg/reclaim/default.go`
- `go.mod` requires `traefik-middleware-utilities v1.0.3`. `pkg/cache` imports its `simpleredis`. Vendor has no `reclaim/` tree.
- Live spec still requires first-wins settings hash, `PeekLivePrefix`, warn-and-wire. `openspec/specs/core_plugin_lapi_reclaim-key/spec.md`
- Store spec still says first-wins `scopes=` and warn-and-wire stay on the Client key. `openspec/specs/core_cache_client_decision-store/spec.md`
- Debt file still open. `knowledge/debt/2026-09-17-cursor-only-reclaim-key.md`

## Desired
- Stream (and the live identity the ticket names) reclaim key is cursor-shaped so routers that disagree on today’s hashed settings share one incarnation, not a sibling slot. Align with the store key in `pkg/lapi/decisionstore.go`.
- Requested `scopes=` is the union of live routers; store filter follows that union.
- Delete `Peek`, `PeekLivePrefix`, and `View`. If sleeping-slot detection is still required for stream ownership, name the replacement; do not keep Peek by inertia.
- Import utilities `reclaim` and keep only the local shim (`Default`, `ProcessGrace`, Open wrappers, test Reset). Evaluate `OpenTyped`: take it only if it removes hooks-as-funcs; otherwise leave the workaround and say why.
- Document upgrade: cache prefix vs old Redis keys.
- Implement later deletes the debt file. Prepare does not.

## Affected
- `pkg/lapi/session.go`, `identity.go`, `client.go`, `client_decisions.go`, `decisionstore.go`, session/plugin tests
- `pkg/reclaim` (table import + delete Peek)
- Specs: `core_plugin_lapi_reclaim-key`, `core_plugin_lapi_stream-lease`, `core_cache_client_decision-store`, `core_plugin_middleware_bouncer`
- `pkg/appsec/session.go` only for reclaim import and the hooks / `OpenTyped` question
- `knowledge/debt/2026-09-17-cursor-only-reclaim-key.md` (close on implement)

## Out of scope
- `pkg/captcha/`
- `pkg/appsec/` beyond reclaim import and hooks
- Prepare deleting the debt file
- Edit of `D:/repositories/traefik-middleware-utilities` or a `vendor/` patch CI would re-vendor
- `atomic.Pointer[T]`; converting existing write-once `Client` scalars into mutable ones
- Union of intervals, Redis, CAPI scenarios, or `updateMaxFailure` (only `scopes=`)
- Changing AppSec reclaim key shape
- CAPI stream `scopes=` (already omitted)

## Unknowns
- Whether `Peek(bindKey)` sleeper retitle is still required after one cursor key, and what replaces it.
- How to hold a live-router scope union without mutating write-once `decisionScopeHeaders`.
- Whether live/none `Key` drops the same remaining fields as stream (ticket names `identity.go`; store already uses `SessionHex` + Redis).
- Exact Client key string versus `StoreKey` (`lapi:stream:` vs `decisionstore:` prefix).
- Whether Redis stays on the Client key (store alignment) or drops with the CrowdSec-row settings (ticket says none of the hashed settings pick the LAPI row).
- Upgrade: if `SessionHex` and store Redis params stay, existing Redis keys stay reachable. If either changes, they become unreachable. Ticket asked for a documented choice.
- `OpenTyped` does not change hook shape (see Tensions).

## Tensions
- Ticket: hashed settings do not pick the CrowdSec row, so disagreeing routers share one incarnation. Store key still hashes Redis. Aligning with the store keeps Redis on the Client key; dropping it would share one Client across Redis hosts.
- Ticket cites `CachePrefix` (`SessionHex` vs `IdentityHex`). That helper is not found; `#66` already prefixes Redis with `SessionHex` for every mode. Changing `SessionKey` alone does not move Redis keys.
- Ticket Peek production sites omit `zzz_plugin_test.go`.
- Union of live scopes vs “do not convert write-once `Client` scalars into mutable ones”.
- Live specs still require first-wins hash, `PeekLivePrefix`, and first-wins `scopes=` on the Client key.
- `OpenTyped` still takes `func() (any, Hooks, error)`. It does not remove hooks-as-function-values. Leave the workaround unless explore finds another surface.
- After a cursor-only key, a sleeping Redis (or interval) change Wakes the same slot. Current spec “Redis host change does not overlap pollers” depends on a new settings-hash key.
- Upstream v1.0.3 lacks Peek; a sidecar cannot read unexported `items`. Missing Peek is expected after part 3, not a blocker. Missing any other needed surface → `blocked`, do not fork.
