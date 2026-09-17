## Context

See proposal.md Why. DestBranch: `SessionKey` is `lapi:stream:` + SessionHex + hash(`streamSettings`) including intervals, Redis, `updateMaxFailure`, CAPI scenarios, and `decisionScopeHeaders` (`pkg/lapi/session.go`). Live/none `Key` is `lapi:` + `IdentityHex` (same remaining knobs except `decisionScopeHeaders`) (`pkg/lapi/identity.go`). `OpenStream` uses `PeekLivePrefix(SessionPrefix)` then `Peek(bindKey)` (`pkg/lapi/session.go`). `streamQuery` / `storeStreamDecision` read write-once `decisionScopeHeaders` (`pkg/lapi/client_decisions.go`). `StoreKey` is already `decisionstore:` + SessionHex + hash(`storeParams`) (`pkg/lapi/decisionstore.go`). Redis prefix is already `SessionHex` for every mode. Local `pkg/reclaim/table.go` matches utilities v1.0.3 except CRLF; `OpenTyped` still takes `func() (any, Hooks, error)` (`reclaim/opentyped.go`). CrowdSec cursor owner is the LAPI bouncer row (`ext_crowdsec_lapi_stream-cursor`). Visitor address owner is `pkg/ip.GetRemoteIP`. Yaegi: Hooks as funcs; no `atomic.Pointer[T]`.

## Goals / Non-Goals

**Goals:**

- One stream Client Open key per cursor + Redis; live/none Key also splits on `MetricsUpdateIntervalSeconds`
- Delete Peek / View; import utilities `reclaim`; keep the local shim
- Live-router `scopes=` union on the Client; store filter follows that union
- Document that Redis keys stay on SessionHex

**Non-Goals:**

- Union of intervals, Redis, CAPI scenarios, or `updateMaxFailure`
- Auto-`startup=true` when the union grows; sweep on shrink
- `OpenTyped`; `atomic.Pointer[T]`; mutating write-once Client scalars
- AppSec reclaim key shape; CAPI `scopes=`; `pkg/captcha/`
- Edit of utilities or a `vendor/` patch
- Rewriting usage packets (implement / `sbs-dev-devdocsimpact`)

## Decisions

1. **Stream Open key** = `lapi:stream:` + `SessionHex(cfg)` + `:` + hash(`storeParamsFrom`). Same hasher as `StoreKey`. Alternative: drop Redis from the Client key — rejected; that would share one Client across Redis hosts. Alternative: reuse `StoreKey` as the Client key string — rejected; one process table, several value types.

2. **Live/none Open key** = `lapi:` + `SessionHex(cfg)` + `:` + hash(`identityFrom`). Keep `MetricsUpdateIntervalSeconds` on the identity payload so none routers that disagree get sibling Clients and their own write-once ticker. Still drop CAPI scenarios, `updateMaxFailure`, and `UpdateIntervalSeconds`. Keep `IdentityHex` exported if callers still name it; it is not the Open suffix. Alternative: drop the metrics interval like stream — rejected; sharing one none Client cannot both honor write-once `metricsInterval` and publish `/appsec` `metrics=1` within 20s. Alternative: mutate write-once `metricsInterval` or start a second ticker — forbidden (`core_plugin_lapi_usage-metrics`). Alternative: keep `IdentityHex` as the live Open suffix — rejected; store already uses SessionHex + Redis.

3. **No Peek.** `Open` of the cursor+Redis key Wakes the sleeper. `PeekLivePrefix` would warn-and-wire a different-Redis joiner onto the first live slot. Tests use pointer equality on the `Open` return or `ResetForTest`. Alternative: keep Peek only to log `ignored` — rejected; Bound the ask.

4. **Scope union registry** lives on the Client. Keyed by constructor ctx. Register after successful `OpenStream` bind with that ctx and this router’s normalized headers. Unregister on ctx Done (holder is Traefik `New` ctx). Snapshot under the existing Client mutex for `streamQuery` and `storeStreamDecision`. Leave `decisionScopeHeaders` write-once at `New`. Alternative: mutate the write-once map — forbidden. Alternative: `atomic.Pointer[T]` — forbidden. Alternative: package global / `sync.Once` — rejected (`std_go_reclaim`).

5. **Union grow / shrink.** No auto-`startup=true` (LAPI `scopes=` filters `id_gt`; document the miss window). No sweep on unregister (TTL / store incarnation). Alternative: force startup on first new scope — out of scope.

6. **Import utilities `reclaim` v1.0.3.** Delete local `table.go` and `peek.go`. Shim keeps `Default`, `ProcessGrace` 30s, `Open` / `OpenWithHooks`, `ResetForTest` / `ResetForTestWith`. Do not take `OpenTyped`. AppSec stays on `OpenWithHooks` + type assert (`pkg/appsec/session.go` import only). Alternative: keep the fork for Peek — rejected; Peek is deleted.

7. **Upgrade.** SessionHex and store Redis params stay. Redis keys unchanged versus DestBranch. Only the in-process Client Open string changes. No key migration. `#66` already prefixes Redis with `SessionHex`.

8. **Identity.** Do not reconstruct the LAPI hop. Reuse `SessionHex` / `streamSession` and `pkg/ip.GetRemoteIP`.

## Risks / Trade-offs

- [Late-joining header scope misses decisions already past the cursor] → Document the miss window. Do not auto-startup.
- [Stale header-scope cache keys after unregister] → TTL / store incarnation. Bound the ask.
- [Silent first-wins on stream intervals / CAPI / `updateMaxFailure`] → Same as create-already-wrote. Out of scope to union them. Live/none metrics interval is on the Key instead (sibling Clients).
- [Sleeping Redis-host change still two keys] → Intended; store isolation stays. Sleeping interval change now Wakes the same slot (spec rewrite).
- [Yaegi Hooks] → Leave function values. `OpenTyped` does not help.

## Migration Plan

- In-process: new Client Open strings; old settings-hash slots die with grace. Same Redis snapshot Wakes.
- Redis: no prefix change; no migration.
- Rollback: revert the change; Client keys return to settings hash / `IdentityHex` suffix; Peek returns. Redis keys still match.

## Open Questions

None that change specs or tasks. Assumed proceed policies live on `devstate/explore.md`.
