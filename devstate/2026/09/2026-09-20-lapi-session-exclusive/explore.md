# Explore

## Concepts

**Traefik middleware name** is Traefik Yaegi’s `New(ctx, next, config, name)` fourth argument (`ext_traefik_plugins_yaegi-constructor`). Traefik calls `New` once per router that lists that named middleware, with the **same** `name` string. It is not a router name, not Host, not a bouncer API key. This change stores that string write-once on the DecisionStore as `createdBy`. Do not put it in a reclaim key.

**DecisionStore** is the expensive session lock and warm cache (`pkg/decisionstore.Store`). Isolation today is reclaim key `decisionstore:` + `SessionHex` + Redis store-params hash. Desired: `decisionstore:` + `SessionHex` only. Exclusive ownership is `createdBy`, not the Client Open key. Redis YAML change reuses the existing engine (first-wins). Client Close does not Close the store.

**LAPI Client** is disposable: stream/metrics tickers and replaceable HTTP. Stream/alone Open key stays `lapi:stream:` + `SessionHex` + Redis hash. Live/none `Key` still hashes Redis + metrics interval. Timeout/TLS stay out; `AdoptTransport` last-wins. A new Client on a warm store must not send `startup=true` when the store already finished a stream poll (`streamReady`).

**CrowdSec stream cursor** lives on the LAPI bouncer row (hashed API key + outbound IP LAPI sees), not per HTTP client (`ext_crowdsec_lapi_stream-cursor`). Two in-process `startup=false` GETs on that row can duplicate or rewind the cursor. Sequential polls are fine; overlapping polls are not. Intra-Client skip is already `streamPollInFlight` CAS (`core_plugin_lapi_stream-single-flight`). Sleep/Close still do not cancel `sendQuery`’s `http.NewRequest` (no context).

**Reclaim holder** is the `bindCtx` child of Traefik `New` ctx (`plugin.go`). Sister pattern in this repo: `pkg/reclaim` shim over utilities table, `ProcessGrace` 30s, `OpenWithHooks`, no `sync.Once`, no package map, no Release API. Failed `New` cancels `bindCtx`. Do not invent globals. Peek is a look without bind: it must not increment holders, must not Wake, must not stop grace.

**Exact Peek** is `Peek(key) → (value, awake|asleep, ok)` on vendored `reclaim/table.go`, re-exported from `pkg/reclaim`. Not `PeekLivePrefix`. Not a local `table.go` fork. Published utilities `v1.0.6` (this plugin’s pin) has no Peek.

```
  New(bindCtx, name)
       │
       ├─ Peek(storeKey) ── hit + createdBy != name ──► error, no Open, no Wake
       │                 └── miss or createdBy == name ──► Open store (bind/Wake)
       │                                                      create() sets createdBy
       └─ Open Client (new or Wake). Read store.streamReady → skip startup=true
```

## Decisions

- Reuse Traefik `New(..., name)` as `createdBy` and as the exclusive-name compare. Same name on many routers shares one store (and one Client when Client keys match). A second **different** name on the same `SessionHex` store fails `New`. Isolation is a second bouncer API key (or a different LAPI host), not a second middleware name on the same key.
- Peek the DecisionStore reclaim key **before** `Open`. Peek hit and `createdBy != name` → return error, do not Open, do not Wake. Peek miss or same name → `Open` store. Pass `name` into `OpenDecisionStore` so create() can write `createdBy`.
- Store reclaim key = `decisionstore:` + `SessionHex` only. Drop the Redis hash. Invert `TestStoreKey_DifferentRedisHostsIsolate` / `TestOpenStream_DifferentRedisIsolatesClientAndStore` store assertions. Client keys may still include Redis (and live metrics interval). Redis YAML change with the **same** name Opens a new Client and reuses the existing store engine (first-wins).
- Rename during 30s grace: Peek still sees the old `createdBy`; `New` fails until the sleeper Closes; Traefik retry self-heals. No table Release. Failed `New` still cancels `plugin.go` `bindCtx`.
- Client Close/Sleep must not Close the store (already true). Store has Close-only hooks (already true). Do not put store-as-child Close on `lapi.Client.Close`.
- `streamReady` on the store after the first finished stream poll. `lapi.New` always sets `isCrowdsecStreamStartup = 1` today; new Client reads `streamReady` and must not send `startup=true` when the store is warm. Mode change → new `SessionHex` → empty store → `startup=true`. Live/none: same exclusive name rule; preserve store; no stream startup flag.
- Client IO: `sendQuery` and live lookups (`crowdsecQuery` → `sendQuery`) use `http.NewRequestWithContext` on a Client `WithCancel` ctx. Sleep and Close cancel it. Wake mints a new `WithCancel`. `drainMetrics` / `reportMetrics` use `context.Background()` so Sleep’s async drain and Close’s sync drain still POST. `closeIdle` stays. AppSec `pkg/appsec/query.go` `NewRequest` stays (out of scope).
- Exact Peek on vendored `table.go` + `pkg/reclaim` re-export. Do not restore `PeekLivePrefix`. Do not re-implement closed PR 119 (share-and-WARN, `sessionResidue`, `liveMiddlewareNames`, store-as-child Close, `PeekLivePrefix`).
- Specs this change must rewrite (propose maps): `core_plugin_lapi_reclaim-key` (two names share → exclusive name; still no `PeekLivePrefix` for retitle/warn-and-wire), `std_go_reclaim_context-lease` (allow exact Peek export; still forbid `PeekLivePrefix` / `View` / table fork), `core_plugin_decisionstore_store` (StoreKey without Redis hash; `createdBy`; Redis first-wins), `core_plugin_lapi_query-round-trip` (request context), plus connection / stream-single-flight / middleware usage packets as needed. `core_plugin_lapi_scope-union` stays for **same-name** many routers, not across names.
- Do not add a `core_plugin_reclaim` packet. Update `std_go_reclaim`, `core_plugin_middleware`, `core_plugin_lapi_reclaim-key`, `core_plugin_decisionstore`. Traefik `New` ctx remains the holder.
- Tests that encode DestBranch share-and-join with **different** names (`TestOpenStream_LiveMetricsMismatchSharesSilently` `owner-mw`/`joiner-mw`, `TestOpenStream_HeaderMapMismatchSharesClient` `country`/`user`, `TestOpenStream_FailureActionOnlyKeepsClient` `first`/`test`) invert to fail the second name, or retarget to the **same** name when they mean many routers / reconfigure. Redis-reload tests that use `first`/`reload` must use one name if they model YAML reconfigure.
- Knowledge/debt: CI vendor restore / upstream Peek. Still ship the ad-hoc Peek.

## Measured DestBranch (origin/master behavior on this worktree)

`go test ./pkg/lapi ./pkg/reclaim -count=1 -run 'TestStoreKey_DifferentRedisHostsIsolate|TestOpenDecisionStore_DifferentRedisHostsIsolate|TestOpenStream_LiveMetricsMismatchSharesSilently|TestOpenStream_SleepingIntervalChangeWakesSameSlot|TestSessionKey_SameLapiKeySharesCursorAndRedisHash|TestKey_NoneMetricsIntervalSplitsClientKeepsStore|TestShim_ProcessGraceAndOpenWithHooks'` → **pass** (2026-09-20, this worktree).

| Claim | Result |
|-------|--------|
| `sendQuery` uses `http.NewRequest` with no context | **reproduced** — `pkg/lapi/client_http.go` POST and GET both `http.NewRequest`. Live lookups go through `crowdsecQuery` → `sendQuery`. No `NewRequestWithContext` in `pkg/lapi`. |
| `Wake` immediately `go handleStreamTicker()` | **reproduced** — `pkg/lapi/client.go` `Wake` after unlocking. CAS in `handleStreamTicker` still serializes overlap **on one Client** while a poll holds `streamPollInFlight`. Sleep does not cancel the in-flight GET. A **new** Client after grace Close can poll while the old GET still runs (no ctx cancel) and `New` still sets `isCrowdsecStreamStartup = 1`. |
| `StoreKey` includes Redis hash | **reproduced** — `StoreKey` is `decisionstore:` + `SessionHex` + `hashJSON(storeParamsFrom)`. `TestStoreKey_DifferentRedisHostsIsolate` passed. |
| `Store` has no `createdBy` / `streamReady` | **reproduced** — `pkg/decisionstore/store.go` `Store` fields are engine/mem/red/origins/range only. |
| `lapi.New` sets `isCrowdsecStreamStartup` to 1 | **reproduced** — `pkg/lapi/client.go` Client literal. `TestOpenStream_SleepingIntervalChangeWakesSameSlot` proves **Wake on the same Client** resumes at 0; it does not cover a new Client on a warm store. |
| Spec forbids Peek | **reproduced** — `openspec/specs/std_go_reclaim_context-lease/spec.md` MUST NOT export `Peek` / `PeekLivePrefix` / `View`. Shim `pkg/reclaim/default.go` re-exports `OpenWithHooks` only. Vendor `table.go` has no `Peek`. |
| Two names share one Client | **reproduced** — `TestOpenStream_LiveMetricsMismatchSharesSilently` (`owner-mw` vs `joiner-mw`) passed; `OpenStream` logs `lapi session joiner adopted` with no name check. `core_plugin_lapi_reclaim-key` scenario “Same LAPI key two names share one stream” is live spec, not a DestBranch bug relative to that spec. This ticket replaces that control plane. |

Overlapping-poll **steal on one Client** via Wake while CAS is held: **not reproduced** as a second GET (CAS drops the Wake poll). The ticket’s IO-cancel still stands so Sleep/Close abort the GET and so a reincarnated Client cannot share the row with a leftover request. CrowdSec LAPI has no cursor lease (`ext_crowdsec_lapi_stream-cursor`).

## Approach (propose / implement, not this phase)

1. Add `State` (`Awake`, `Asleep`) and `(*Table).Peek` on vendored `table.go`. Re-export from `pkg/reclaim`. Tests in `pkg/reclaim` (`zzz_` prefix) and a vendor table test if utilities tests live next to `table.go`.
2. `Store.createdBy` write-once in store `Open` create(). `Store.streamReady` set from the first finished stream poll. `OpenDecisionStore(ctx, cfg, log, name)`.
3. `OpenStream` / `OpenLive`: Peek store key; reject other names with `log.Error` + returned error (owner, rejected, clears when old slot Closes, isolation is a second bouncer API key). Then Open store, then Open Client. New Client reads `streamReady`.
4. `StoreKey` drops Redis hash. Client `SessionKey` / live `Key` keep Redis (and live metrics).
5. Client IO ctx + `NewRequestWithContext`. Metrics drain on `Background`.
6. Rewrite the specs named above. Invert share-and-join tests. Keep AppSec reclaim as-is.

## Open questions

- Q: Who already owns the middleware identity this work would store as DecisionStore `createdBy`?
  Decision: resolved — Traefik Yaegi `New(ctx, next, config, name)` (`ext_traefik_plugins_yaegi-constructor`). Reuse that `name`. Do not reconstruct from router name, Host, or a second registry. Do not put name in the reclaim key.
  By: explore

- Q: What exact Go types does Peek use for the awake\|asleep triple?
  Decision: assumed — vendored `func (t *Table) Peek(key string) (value any, state State, ok bool)` with exported `type State int` and `const (Awake State = iota; Asleep)`. `pkg/reclaim` type-aliases `State` and re-exports `Awake` / `Asleep` / `Peek` on `Default()`. `ok=false` for missing, gone, or busy (do not wait, do not bind). Map from unexported `slotAwake` / `slotAsleep` only; never return busy as a State.
  By: explore

- Q: Does Peek wait when the slot is `slotBusy` (create/Wake/Sleep in flight)?
  Decision: assumed — no; `ok=false`. Caller then `Open`s only on miss-or-same-name from a non-busy Peek. Parallel-create of two different names is out of scope (no table closer). Do not add a post-Open `createdBy` check.
  By: explore

- Q: Does an empty Traefik `name` still exclusive-own the store?
  Decision: assumed — yes; empty is still the owner string. Two empty names share. A non-empty name still fails Peek against empty `createdBy`.
  By: explore

- Q: How is `streamReady` stored so Yaegi v0.16 stays safe?
  Decision: assumed — `int64` field on `Store` with `atomic.LoadInt64` / `StoreInt64` (same as Client stream flags). Do not use `atomic.Bool` or `atomic.Int64` as a struct field. Set after the first stream poll that finished (`handleStreamCache` success path). New Client reads it before the first GET.
  By: explore

- Q: Does a later `go mod vendor` that restores published utilities v1.0.6 keep Peek?
  Decision: assumed — no, it would drop Peek. Ship the vendor method now. Debt `knowledge/debt/2026-09-20-upstream-reclaim-peek.md`: upstream Peek and only then re-enable CI vendor git-diff. Current CI comments that diff out, so this patch survives today’s workflow.
  By: explore

- Q: Should explore/propose add a `core_plugin_reclaim` usage packet?
  Decision: assumed — no. `std_go_reclaim` and `core_plugin_middleware` already own New-ctx reclaim. Update those plus `core_plugin_lapi_reclaim-key` and `core_plugin_decisionstore`. Do not fold exclusive-name into AppSec.
  By: explore
