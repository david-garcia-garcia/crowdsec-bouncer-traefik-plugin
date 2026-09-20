Title: One middleware name owns a LAPI session; keep DecisionStore across Client reincarnation; Peek then fail; session-scoped stream skip

Supersedes closed PR 119 / 2026-09-20-lapi-session-subscribe (share-and-WARN was the wrong control plane).

### Exclusive ownership
Two different Traefik middleware **names** must not share LAPI scheme+host+path+key. Fail `New` for the second. Same name on many routers is the same middleware and MUST share.

Detection: exact Peek on the DecisionStore reclaim key (no bind). Store holds write-once `createdBy` (Traefik name from the New that ran create()). Peek hit and createdBy != this name → error, do not Open, do not Wake. Peek miss or same name → Open store.

Routers are instantiated sequentially; do not design a parallel first-create race as product work.

Rename foo→bar during 30s grace: Peek still sees createdBy=foo, New fails until the sleeper Closes; Traefik retries and it self-heals. **Required:** a loud operator log/error: who owns the session, who was rejected, that it clears when the old slot Closes, that isolation is a second bouncer API key not a second middleware on the same key.

No table Release API. Failed New still cancels plugin.go bindCtx for anything this constructor already Opened.

### Store is the expensive object; Client is disposable
DecisionStore reclaim key = `decisionstore:` + SessionHex only (mode + LAPI scheme/host/path + lapiKey / CAPI in alone). **No Redis hash.** This row is the session lock and the warm cache.

`lapi.Client` may still reclaim with Redis/intervals in the key so a YAML reconfigure creates a **new** Client. Timeout and TLS stay **out** of the Client key: same Client + AdoptTransport last-wins (existing).

Reconfigure (same middleware name, same mode): Open the same store (bind/Wake); new or Woken Client; do **not** `startup=true`. Put **streamReady** and **streamPollInFlight** on the store (they own the CrowdSec cursor+applied cache, not this HTTP client). New Client reads streamReady and must not zero either flag. Mode change (stream↔live/alone) → different SessionHex → new empty store → startup=true.

Client Close must **not** Close the store (master already). Do not make store a child of Client Close.

Redis YAML change with session-only StoreKey reuses the existing store backend (first-wins memory vs Redis host). No migrate. No second ticker.

Live/none: same exclusive name rule; preserve store (live cache); no stream startup flag.

AppSec reclaim unchanged.

### Session-scoped stream skip (do not cancel in-flight GET)
Cancelling an in-flight stream GET loses deltas (LAPI already advanced the cursor). Overlap is fixed by session-scoped skip, not abort.

`streamReady` and `streamPollInFlight` live on DecisionStore, not Client. handleStreamTicker (and Wake's immediate poll) skip if store streamPollInFlight is set (CAS). Sleep does not wait. Do not cancel the in-flight Do. Do not add a Client IO context. sendQuery stays `http.NewRequest`.

Close: still stop tickers and closeIdle; do not add a cancel ctx. An in-flight poll may finish apply after Close starts; that is acceptable vs losing the cursor window.

drainMetrics unchanged (no IO ctx). Timeout stays off Client reclaim key; AdoptTransport on the same Client.

### Peek API
Exact Peek(key) → (value, awake|asleep, ok) without binding. Implement on vendored `traefik-middleware-utilities/reclaim` table.go and export via `pkg/reclaim`. No PeekLivePrefix. No fork of the whole table into pkg/reclaim.

### Out of scope
Share-and-WARN subscribe; sessionResidue field lists; liveMiddlewareNames registry; PeekLivePrefix warn-and-wire; store-as-child Close; failing New on timeout-only reload; two Traefik processes; memory↔Redis migrate; parallel-create race closer.
