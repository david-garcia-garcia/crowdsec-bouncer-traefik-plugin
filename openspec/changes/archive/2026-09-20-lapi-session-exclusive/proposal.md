## Why

Two Traefik middleware names that share LAPI scheme+host+path+key currently Open the same DecisionStore and Client. That is the wrong control plane: the store is the expensive session lock and warm cache. A new Client on a warm store can send `startup=true`, and a leftover stream GET plus Wake can overlap CrowdSec `stream_cursor` polls. Cancelling that leftover GET would drop deltas LAPI already advanced.

## What Changes

- Exact Peek on the DecisionStore reclaim key before Open. Store `createdBy` is Traefik `New(..., name)` from the create() that first put the store. Peek hit and `createdBy != name` → error, do not Open, do not Wake. Peek miss or same name → Open store. Same name on many routers still shares. A second **different** name on the same LAPI session fails `New`.
- Loud operator error: owner name, rejected name, clears when the old slot Closes, isolation is a second bouncer API key not a second middleware on the same key. Rename during 30s grace fails until Close; Traefik retry self-heals. No table Release. Failed `New` still cancels `plugin.go` bindCtx.
- Store reclaim key = `decisionstore:` + SessionHex only (drop Redis hash). Client keys may still include Redis (and live metrics interval). Timeout/TLS stay out; `AdoptTransport` last-wins. Redis YAML change reuses the existing store engine (first-wins). Client Close must not Close the store.
- `streamReady` and `streamPollInFlight` on the store (CrowdSec cursor+applied cache, not this HTTP client). A new Client on a warm store must not send `startup=true` and must not zero those flags. handleStreamTicker and Wake skip when the store CAS is held. Mode change → new SessionHex → empty store → `startup=true`. Live/none: same exclusive name; preserve store; no stream startup flag.
- Do not add a Client IO cancel context. `sendQuery` stays `http.NewRequest`. Sleep does not wait or cancel Do. Close stops tickers and `closeIdle` only. `drainMetrics` unchanged.
- Exact `Peek(key) → (value, State, ok)` on vendored utilities `reclaim/table.go`, re-exported from `pkg/reclaim`. No `PeekLivePrefix`. No fork of the whole table into `pkg/reclaim`. Upstream Peek / CI vendor git-diff stays a noted follow-up; this change still ships the ad-hoc Peek.

## Capabilities

### New Capabilities

(none)

### Modified Capabilities

- `core_plugin_lapi_reclaim-key`: exclusive Traefik name owns the DecisionStore session (Peek then fail a different name). Same name on many routers still shares. Client Open keys stay Redis-aware. Do not restore `PeekLivePrefix` warn-and-wire.
- `std_go_reclaim_context-lease`: allow exact `Peek` export on the vendor table plus shim; still forbid `PeekLivePrefix`, `View`, and a local `table.go` fork.
- `core_plugin_decisionstore_store`: StoreKey is `decisionstore:` + SessionHex only; write-once `createdBy`; `streamReady` and `streamPollInFlight` on the store; Redis YAML change first-wins the existing engine.
- `core_plugin_lapi_stream-single-flight`: a new Client reads store `streamReady` before the first GET; skip is store `streamPollInFlight` CAS (not a Client IO cancel).
- `core_plugin_middleware_bouncer`: a second **different** Traefik name on the same LAPI session fails `New`; same name on many routers still shares one store (and one Client when Client keys match). Failed `New` still releases bindCtx.

## Impact

- `plugin.go`, `pkg/lapi/session.go`, `pkg/lapi/decisionstore.go`, `pkg/lapi/client.go`, `pkg/lapi/client_http.go`, `pkg/lapi/client_stream.go`, `pkg/lapi/client_decisions.go`, `pkg/decisionstore/store.go`, `pkg/reclaim/default.go`, vendored `traefik-middleware-utilities/reclaim/table.go`, tests under `pkg/lapi` / `pkg/reclaim` / `pkg/decisionstore`
- Invert DestBranch share-and-join tests that use two different names; retarget YAML-reconfigure tests to one name
- Debt already noted: `knowledge/debt/2026-09-20-upstream-reclaim-peek.md`
- Usage packets `std_go_reclaim`, `core_plugin_middleware`, `core_plugin_lapi_reclaim-key`, `core_plugin_decisionstore` after apply (devdocsimpact). Do not add `core_plugin_reclaim`
- No **BREAKING** public JSON/YAML keys. AppSec reclaim unchanged
- Out of scope: closed PR 119 (share-and-WARN, `sessionResidue`, `liveMiddlewareNames`, store-as-child Close, `PeekLivePrefix`); two Traefik processes; memory↔Redis migrate; parallel-create race closer
