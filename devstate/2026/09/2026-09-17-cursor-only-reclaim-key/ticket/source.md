# Narrow the LAPI reclaim key to the CrowdSec cursor row

This ticket takes the follow-up recorded in `knowledge/debt/2026-09-17-cursor-only-reclaim-key.md`. That file is the ticket source. It has four parts and they are one story.

This is the last step of a five-change series. `master` is currently `45b4a4a`. Read these archived changes before designing anything:

- `openspec/changes/archive/2026-09-17-lapi-transport-router-policy/`
- `openspec/changes/archive/2026-09-17-appsec-transport-reclaim-split/`
- `openspec/changes/archive/2026-09-17-extract-metrics-reporter/`
- `openspec/changes/archive/2026-09-17-shared-decision-store/`

Live spec leaves:

- `openspec/specs/core_plugin_lapi_reclaim-key/spec.md`
- `openspec/specs/core_plugin_lapi_stream-lease/spec.md`
- `openspec/specs/core_cache_client_decision-store/spec.md`
- `openspec/specs/core_plugin_middleware_bouncer/spec.md`

## 1. Narrow the LAPI reclaim key to the CrowdSec cursor row

CrowdSec keeps `GET /v1/decisions/stream` progress on one bouncer row, selected by a hash of the lapiKey plus Traefik's outbound IP. None of the hashed settings affect that row.

Today the key is still the session prefix plus a first-wins hash of the remaining settings (`SessionKey` / `settingsFrom` / `streamSettings` in `pkg/lapi/session.go`, and `identity` in `pkg/lapi/identity.go`). Make the key cursor-shaped so that routers that disagree on those settings share one incarnation instead of warn-and-wiring into a sibling slot. Align it with the store key that `pkg/lapi/decisionstore.go` already uses.

## 2. Union `scopes=` across the live routers instead of first-wins

Today `streamQuery()` in `pkg/lapi/client_decisions.go` builds `&scopes=` from `c.decisionScopeHeaders`, which is whichever router constructed the Client first; `storeStreamDecision` then filters header scopes by that same map. Once routers share one incarnation, first-wins silently drops a second router's scopes. Make the requested scope set the union of the live routers, and make sure the store filter follows the union rather than one router's view.

## 3. Delete `Peek`, `PeekLivePrefix` and `View`

They exist only for the warn-and-wire path that part 1 removes. The only production call sites are `pkg/lapi/session.go` (`reclaim.PeekLivePrefix(SessionPrefix(cfg))` and `reclaim.Peek(bindKey)`), plus `pkg/lapi/zzz_session_test.go` and `pkg/reclaim/zzz_peek_test.go`. If after part 1 you still need to know whether a slot is sleeping in order to transfer stream ownership, say so explicitly and explain what replaces it — do not keep `Peek` by inertia.

## 4. Turn `pkg/reclaim` into a real import of the upstream module, keeping only a thin local shim

`go.mod` already requires `github.com/david-garcia-garcia/traefik-middleware-utilities v1.0.3`, and `pkg/cache` already imports its `simpleredis` package directly. The reclaim half never finished the move: PR #56 synced `pkg/reclaim/table.go` from upstream and added `peek.go` as the local delta, and that delta is the only reason the fork still exists. Upstream's `reclaim` package has `New`, `Table`, `Open`, the hooks and an `opentyped.go`, but no `Peek`/`PeekLivePrefix`/`View`. After part 3, what remains local is plugin policy only: `Default()`, `ProcessGrace = 30 * time.Second`, `Open`/`OpenWithHooks` convenience wrappers, and `ResetForTest` / `ResetForTestWith`. Keep that as a small shim and import the table.

While you are there, evaluate upstream's `opentyped.go`: it may let you delete this workaround, which exists because the reclaim table stores `any`:

```
// clientHooks is Sleep/Wake/Close as funcs: Yaegi panics on asserting a foreign concrete type.
```

If `OpenTyped` removes the need for hooks-as-function-values in `pkg/lapi/session.go` and `pkg/appsec/session.go`, take it. If it does not, leave the workaround and say why.

A read-only local clone of the upstream module is at `D:/repositories/traefik-middleware-utilities` — use it to read the upstream API and its `reclaim/BUGS.md`. Do NOT edit that repository, and do NOT patch anything under a `vendor/` directory that CI would re-vendor. If upstream genuinely lacks something this ticket needs, report `blocked` with the specific missing surface instead of forking again.

This plugin runs under Traefik's Yaegi interpreter, and `pkg/reclaim/peek.go` and `table.go` carry local workarounds for real Yaegi v0.16 bugs. Before you delete a local file, confirm the upstream copy still handles the bug that comment describes; if it does not, that is a `blocked` finding. Also: do NOT use `atomic.Pointer[T]` (Yaegi cannot take a generic instantiation from another package as a struct field — use `atomic.Value` with a comment), and do NOT convert existing write-once `Client` scalars into mutable ones.

One migration consequence you must call out: the cache prefix is derived from the reclaim identity (`CachePrefix` in `pkg/lapi/session.go` uses `SessionHex` for stream/alone and `IdentityHex` for live/none). Changing the key shape changes those prefixes, so existing Redis entries written by an older plugin version become unreachable after upgrade. Decide and document the behaviour on upgrade.

Leave `pkg/captcha/` alone, and touch `pkg/appsec/` only for the reclaim import and the hooks question.

When implement later lands the work, close the debt per Issues: delete `knowledge/debt/2026-09-17-cursor-only-reclaim-key.md` and record the closure. That is the last open debt of this series. Prepare does NOT delete the debt file.
