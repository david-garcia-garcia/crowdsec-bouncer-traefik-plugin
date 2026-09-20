## Context

See `proposal.md` Why. DestBranch `master` `OpenStream` / `OpenLive` Open the DecisionStore then the Client with no name check (`pkg/lapi/session.go`). `StoreKey` is `decisionstore:` + SessionHex + Redis hash (`pkg/lapi/decisionstore.go`). `sendQuery` uses `http.NewRequest` with no context (`pkg/lapi/client_http.go`). `lapi.New` always sets `isCrowdsecStreamStartup` to 1. Vendored utilities reclaim (`v1.0.6`) has Open/OpenWithHooks only. Live spec `core_plugin_lapi_reclaim-key` requires two names to share one stream Client; `std_go_reclaim_context-lease` forbids Peek. Identity owner is Traefik Yaegi `New(..., name)` — reuse that string as `createdBy`; do not invent a second registry.

FindSpecHost (search: `openspec/specs/map.md`, live `openspec/specs/*/spec.md`, this change folder empty):

```
verdicts:
  - { deltaId: exclusive-name-peek-fail, fold|new: fold, spec-id: core_plugin_lapi_reclaim-key, confidence: high, candidates: [core_plugin_lapi_reclaim-key, core_plugin_decisionstore_store, core_plugin_middleware_bouncer] }
  - { deltaId: exact-peek-export, fold|new: fold, spec-id: std_go_reclaim_context-lease, confidence: high, candidates: [std_go_reclaim_context-lease] }
  - { deltaId: store-key-createdby-streamready, fold|new: fold, spec-id: core_plugin_decisionstore_store, confidence: high, candidates: [core_plugin_decisionstore_store, core_plugin_lapi_reclaim-key] }
  - { deltaId: query-io-context, fold|new: fold, spec-id: core_plugin_lapi_query-round-trip, confidence: high, candidates: [core_plugin_lapi_query-round-trip, core_plugin_lapi_connection] }
  - { deltaId: client-io-ctx-lifecycle, fold|new: fold, spec-id: core_plugin_lapi_connection, confidence: high, candidates: [core_plugin_lapi_connection, core_plugin_lapi_query-round-trip, core_plugin_lapi_usage-metrics] }
  - { deltaId: new-client-reads-streamready, fold|new: fold, spec-id: core_plugin_lapi_stream-single-flight, confidence: high, candidates: [core_plugin_lapi_stream-single-flight, core_plugin_decisionstore_store, core_plugin_lapi_connection] }
  - { deltaId: middleware-same-name-share, fold|new: fold, spec-id: core_plugin_middleware_bouncer, confidence: high, candidates: [core_plugin_middleware_bouncer, core_plugin_lapi_reclaim-key] }
```

All seven are one–three-requirement adjustments of existing leaves. Do not add `core_plugin_reclaim`. `core_plugin_lapi_scope-union` stays for same-name many routers. `core_plugin_lapi_usage-metrics` stays: drain-on-Background is owned by query-round-trip + connection. No vague-family Issues.

## Goals / Non-Goals

**Goals:**

- One Traefik name owns one SessionHex DecisionStore. Peek then fail a different name without bind/Wake.
- StoreKey drops the Redis hash. Client keys may still include Redis (and live metrics interval).
- A new Client on a warm store does not send `startup=true`.
- Sleep/Close abort in-flight LAPI GET; metrics drain still POSTs.
- Exact Peek on vendor `table.go` + `pkg/reclaim` export.

**Non-Goals:**

- Re-implementing closed PR 119 (share-and-WARN, `sessionResidue`, `liveMiddlewareNames`, store-as-child Close, `PeekLivePrefix`).
- Forking the whole table into `pkg/reclaim`. `View`. Waiting on `slotBusy`.
- A post-Open `createdBy` race closer. Two Traefik processes. Memory↔Redis migrate.
- Changing AppSec reclaim. Failing `New` on timeout-only reload.
- Upstream Peek in published utilities or re-enabling CI vendor git-diff (already noted).

## Decisions

1. **Reuse Traefik `New(..., name)` as `createdBy`.** Compare that string. Empty is still the owner. Do not put name in a reclaim key. Alternative: a `liveMiddlewareNames` registry — rejected (PR 119, second owner of identity).

2. **Peek the DecisionStore key before `OpenDecisionStore`.** Hit + `createdBy != name` → `log.Error` + returned error (owner, rejected, clears when old slot Closes, isolation is a second bouncer API key). Miss or same name → `Open` (bind/Wake). Pass `name` into `OpenDecisionStore` so create() writes `createdBy` write-once. Alternative: Open then check — rejected (Wake on the wrong owner). Alternative: PeekLivePrefix warn-and-wire — rejected (ticket + PR 119).

3. **Peek signature on vendored `table.go`:** `func (t *Table) Peek(key string) (value any, state State, ok bool)` with exported `type State int` and `const (Awake State = iota; Asleep)`. Shim type-aliases `State` and re-exports `Awake` / `Asleep` / `Peek` on `Default()`. Under `t.mu`, do not wait on `slot.ready`. `ok=false` for missing, gone, or `slotBusy`. Map `slotAwake` / `slotAsleep` only; never return busy as a State. Peek MUST NOT increment holders, MUST NOT Wake, MUST NOT stop grace. Alternative: wait on busy — rejected (explore). Alternative: local `table.go` fork — rejected.

4. **`StoreKey` = `decisionstore:` + SessionHex only.** Drop `hashJSON(storeParamsFrom)`. Invert store-isolation tests. Client `SessionKey` / live `Key` keep Redis (and live metrics). Redis YAML change with the same name Opens a new Client and reuses the existing store engine (first-wins memory vs Redis host). Alternative: keep Redis on StoreKey — rejected (ticket: store is the session lock).

5. **`streamReady` and `streamPollInFlight` are `int64` on `Store`** with `atomic.LoadInt64` / `StoreInt64` / `CompareAndSwapInt64` (Yaegi: not `atomic.Bool` / `atomic.Int64`). They own the CrowdSec cursor+applied cache, not this HTTP client. `lapi.New` / Open / Wake MUST NOT zero them. `streamReady` is set on the `handleStreamCache` success path. `lapi.New` reads it before the first GET: non-zero → `isCrowdsecStreamStartup = 0`. `handleStreamTicker` and Wake skip when the store CAS is held. Mode change → new SessionHex → empty store → startup=true. Live/none: exclusive name only; no stream startup flag. Alternative: keep the flags only on Client — rejected (Client is disposable).

6. **No Client IO cancel context.** `sendQuery` stays `http.NewRequest`. Sleep does not wait and does not cancel Do. Close stops tickers and `closeIdle` only; an in-flight poll may finish apply after Close starts. `drainMetrics` unchanged. Alternative: cancel the in-flight GET — rejected (LAPI already advanced `stream_cursor`; abort drops the body). Alternative: wait in Sleep — rejected (ticket: skip, do not wait).

7. **Failed `New` still cancels `plugin.go` bindCtx.** Peek-fail happens before store Open; cancel is still correct. No table Release. Rename during 30s grace: Peek still sees the old `createdBy`; Traefik retry self-heals after Close.

8. **Tests.** Invert DestBranch share-and-join with **different** names (`TestOpenStream_LiveMetricsMismatchSharesSilently` `owner-mw`/`joiner-mw`, `TestOpenStream_HeaderMapMismatchSharesClient` `country`/`user`, `TestOpenStream_FailureActionOnlyKeepsClient` `first`/`test`) to fail the second name, or retarget to the **same** name when they mean many routers / reconfigure. Redis-reload tests that use `first`/`reload` MUST use one name. Invert `TestStoreKey_DifferentRedisHostsIsolate` / store half of `TestOpenStream_DifferentRedisIsolatesClientAndStore`. Peek tests in `pkg/reclaim` (`zzz_` prefix). Vendor tree has no reclaim tests next to `table.go`.

9. **Vendor Peek is the shipped workaround.** Do not skip it. Debt `knowledge/debt/2026-09-20-upstream-reclaim-peek.md` already notes CI `go mod vendor` restore and upstream Peek.

## Risks / Trade-offs

- [Published utilities `v1.0.6` has no Peek; a later `go mod vendor` drops the method] → Ship the vendor method now. Keep the debt note. Current CI comments vendor git-diff out, so today’s workflow keeps the patch.
- [Peek `ok=false` on busy then Open can race two different names] → Out of scope (ticket: sequential routers). Do not add a post-Open closer.
- [Rename during grace fails `New` until Close] → Required. Operator error names the owner and that it clears when the old slot Closes.
- [Redis YAML change first-wins the engine] → Same as today’s store create() first-wins, now across hosts because StoreKey dropped the hash. Client still isolates by Redis.
- [In-flight GET may finish apply after Close] → Acceptable vs losing the cursor window. Store CAS still prevents a second poll.

## Migration Plan

No operator JSON/YAML key change. Isolation of two middleware names that used to share one LAPI key becomes: use a second bouncer API key (or a different LAPI host). Rollback is revert. Existing Redis keys stay prefixed with SessionHex.

## Open Questions

None that change specs, approach, or tasks. Explore rows honored: Peek types `State`/`Awake`/`Asleep`; busy → `ok=false`; empty name owns; store `streamReady` + `streamPollInFlight`; no Client IO cancel; vendor Peek debt; no `core_plugin_reclaim` packet.
