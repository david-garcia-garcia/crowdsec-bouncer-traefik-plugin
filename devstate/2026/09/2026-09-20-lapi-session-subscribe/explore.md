# Explore

## Concepts

CrowdSec LAPI stores one `GET /v1/decisions/stream` cursor and one usage-metrics window on the **bouncer row** selected by SHA-512 of `X-Api-Key` plus the IP LAPI sees (this process’s outbound address). Two in-process tickers that share that pair steal `startup=false` deltas and POST two metrics windows. Isolation needs a second bouncer API key (or a different LAPI host / a different outbound IP). Middleware name, Redis, intervals, and Traefik router count are not how LAPI picks the row. Research: `knowledge/research/ext_crowdsec_lapi_stream-cursor`, `knowledge/research/ext_crowdsec_lapi_usage-metrics`.

DestBranch (this worktree, `master`) still hashes Redis store params into the stream Client Open key. `SessionKey` is `lapi:stream:` + `SessionHex` + `hash(storeParamsFrom)` (`pkg/lapi/session.go`). Live/none `Key` is `lapi:` + `SessionHex` + hash of identity (Redis + `MetricsUpdateIntervalSeconds`) (`pkg/lapi/identity.go`). `SessionHex` includes **mode**, so stream and live never share a Client or a StoreKey even on the same LAPI URL+key.

Measured `go test ./pkg/lapi -count=1 -run "TestOpenStream_DifferentRedis|TestOpenStream_SleepingRedis|TestOpenStream_LiveMetricsMismatch|TestOpenStream_SleepingInterval"`: **PASS** (four tests). DestBranch contract:

- `TestOpenStream_DifferentRedisIsolatesClientAndStore` — different `redisCacheHost` → two Clients and two DecisionStores.
- `TestOpenStream_SleepingRedisHostDoesNotOverlapPollers` — sleeper + Redis host change → new Client; old ticker stays Sleep’d.
- `TestOpenStream_LiveMetricsMismatchSharesSilently` — interval mismatch on a live sibling → one Client, no warn-and-wire (silent first-wins).
- `TestOpenStream_SleepingIntervalChangeWakesSameSlot` — sleeper + interval change, same Redis → Wake, `startup=false`.

Verbose logs showed two Redis snapshots as distinct suffixes on the same SessionHex (`lapi:stream:<hex>:<redisHash>`). That is the false isolation this ticket inverts for stream/alone.

Traefik `New` is per router-handler build, not per process and not per middleware alias (`knowledge/research/ext_traefik_plugins_yaegi-constructor`). Two routers listing the same named middleware each bind a constructor ctx. Join vs reload is reclaim table state for one Open key (`vendor/.../reclaim/table.go` `lookupOpen`): unmapped / `slotGone` → create; `slotAwake` → bind; `slotAsleep` → Wake then bind. There is no `Peek` / `PeekLivePrefix` in this tree. `std_go_reclaim` / `pkg/reclaim`: constructor ctx (here `bindCtx`) is the holder; last holder Sleeps; Open during grace Wakes; do not use `sync.Once` or package globals.

Today `OpenStream` / `OpenLive` Open DecisionStore on the constructor ctx **first**, then Client (`pkg/lapi/session.go`). Store reclaim key is `decisionstore:` + `SessionHex` + Redis params (`pkg/lapi/decisionstore.go`). Client Close does not Close the store (`pkg/lapi/client.go`). Those keys stay in lockstep only because both include Redis. Dropping Redis from the Client key while leaving the sibling store Open would bind a joiner’s unused store on a different Redis key (zombie). Fix: store Open moves into Client `create()`; Store Close becomes the Client Close hook; Redis keys stay prefixed with `SessionHex` (no migration).

Holder middleware names are not recorded. `clientFromStored` uses `middlewareName` only for the type-assert error and AdoptTransport INFO `joiningMiddleware`. Header maps already union via `liveHeaderScopes` keyed by constructor ctx (`pkg/lapi/liveheaderscopes.go`). AdoptTransport last-wins TLS/timeout (`pkg/lapi/client_http.go`). First create logs `crowdsec connection started`, not that this LAPI key owns the process-wide stream/metrics.

README Note already says one stream per LAPI key + outbound IP and that a second config needs a different key; it also says interval / `updateMaxFailure` / CAPI are create-time first-wins. It does not say Redis/interval disagreements are ignored rather than isolated. DestBranch code still isolates by Redis. That tension stays until apply inverts the tests.

Usage packets `core_plugin_lapi_reclaim-key`, `core_plugin_middleware`, `core_plugin_decisionstore` describe DestBranch (Redis on the Client key, sibling store Open). Propose / devdocsimpact update them. No research rewrite: the three packets cover LAPI physics and Traefik `New`.

```
Traefik New (per router) ── bindCtx ──► reclaim.OpenWithHooks(SessionKey)
                                              │
                         unmapped/gone        │ slotAwake          slotAsleep
                              ▼               ▼                    ▼
                           create()         bind (subscribe)     Wake(startup=false)
                              │               │                    │
                     New Client + child Store │                    keep Store+cursor
                     INFO: this key owns      WARN ignored fields + holder names
                     stream/metrics in this
                     process
```

## Decisions

- Stream/alone Open key becomes the LAPI session only: `lapi:stream:` + `SessionHex` (mode + scheme/host/path + lapiKey, CAPI in alone). Drop the Redis hash from `SessionKey`. Do not key by middleware name, outbound IP, or LAPI host alone.
- Join vs reconfigure is table state (bind / Wake / create). Do not Peek. Do not fail `New`. Do not `startup=true` because YAML changed.
- On bind or Wake, reuse the existing Client and its child DecisionStore. First-wins for session-owned knobs with WARN (fields + holder names + “isolation needs a second bouncer API key”). TLS/timeout stay AdoptTransport last-wins. `decisionScopeHeaders` stay live union. Per-router policy stays on Bouncer.
- DecisionStore is created only inside Client `create()`. Client Close Closes the store. Sleep/Wake keep it. `SessionHex` remains the Redis key prefix. No memory↔Redis migrate.
- Invert the Redis-isolation tests to share+WARN. Invert silent interval mismatch to WARN. Sleeping Redis host change Wakes the same slot (keep store) and WARNs; it no longer Opens a second ticker.
- Live/none `Key` is not this ticket’s stream invert: keep Redis and `MetricsUpdateIntervalSeconds` on live identity (see Open questions).
- Do not merge stream and live into one Client or one MetricsReporter (mode stays in `SessionHex`; prefixes stay `lapi:stream:` vs `lapi:`).

## Open questions

- Q: Whether stream+live on the same key should share one metrics reporter.
  Decision: assumed — no. Mode is part of `SessionHex` and the Open prefixes differ (`lapi:stream:` vs `lapi:`), so stream and live never share a Client today and will not after this change. Each Client keeps the `MetricsReporter` it already owns (`core_plugin_lapi_usage-metrics`). A cross-mode reporter would be a new reclaim identity without mode — extra product work. Operators who run both modes on one API key still POST two windows to one CrowdSec row; isolation remains a second bouncer key. README can say that; do not build a shared reporter.
  By: explore

- Q: Whether live/none Client Key also drops Redis the same way.
  Decision: assumed — no, not in this ticket. Desired stream key drop is the cursor-theft path. Live `?ip=` does not steal `stream_cursor`; `plugin.go` already treats two live Clients on one key as valid. Live `Key` keeps Redis store params and `MetricsUpdateIntervalSeconds` (write-once metrics ticker; `TestKey_NoneMetricsIntervalSplitsClientKeepsStore`). Tension stays: stream ignores Redis disagreement, live still isolates by Redis. Do not invert live Key tests except as a side effect of store-as-child (see store question).
  By: explore

- Q: Who already owns LAPI-session identity / outbound IP / middleware name?
  Decision: resolved — reuse those owners; do not reconstruct. LAPI-session identity is `lapi.sessionFrom` / `SessionHex` (`pkg/lapi/session.go`: mode + LAPI scheme/host/path + lapiKey, CAPI machine+password in alone). The new stream Open key is that identity with the Redis hash removed. Outbound IP has no owner in this plugin: CrowdSec LAPI’s API-key middleware maps the process outbound address to a bouncer row; do not put that IP in the reclaim key. `pkg/ip.GetRemoteIP` owns the **visitor** address on the request path (`core_plugin_ip`) — do not reuse it as outbound. Middleware name is Traefik `New`’s fourth argument, passed through `plugin.go` `name` into `OpenStream` / `OpenLive`; reuse that string as the holder-set member.
  By: explore

- Q: How subscribe detects live vs Sleep/Wake vs empty (reclaim table state; Traefik New is per router).
  Decision: resolved — `reclaim.OpenWithHooks` already classifies: empty/unmapped/`slotGone` → `create()`; `slotAwake` → bind (ticket “subscribe”); `slotAsleep` → Wake then bind (`startup=false`, store+cursor kept). Traefik `New` per router means two routers are two binds even when the middleware alias is the same. The Open caller records whether its `create` closure ran (local flag). Create → first-create INFO (this LAPI key owns the process-wide stream/metrics). `!created` (bind or Wake) → subscribe WARN path if session-owned knobs differ. Do not Peek. Do not key off middleware name to detect reload.
  By: explore

- Q: How DecisionStore becomes a child of Client create() without Redis key migration (StoreKey/SessionHex stay).
  Decision: resolved — `create()` calls `decisionstore.NewMemory` / `NewRedis` (or the existing constructors) with `keyPrefix = SessionHex`. Do not `OpenDecisionStore` from `OpenStream` / `OpenLive` on the constructor ctx. `StoreKey` may stay as a composition helper; it is not a sibling reclaim Open for this Client. Redis logical keys stay under `SessionHex` (upgrade: no key migration). Client Close hook Closes the store; Sleep/Wake do not. Side effect of dropping the sibling Open: live/none Clients that still split on `MetricsUpdateIntervalSeconds` no longer share a reclaim Store (today they share `StoreKey`). Memory backends isolate; Redis backends still share keys via `SessionHex`. Do not keep a sibling store Open to preserve that share — that is the zombie hazard for stream Redis drop.
  By: explore

- Q: WARN field list vs first-wins vs AdoptTransport last-wins vs live header union.
  Decision: resolved — one compare of joiner YAML against create-time residue on the Client (capture store params + interval / `updateMaxFailure` / CAPI scenarios at `create()`, like write-once `decisionScopeHeaders`). First-wins + WARN every ignored field, plus holder names, plus isolation needs a second bouncer API key: `redisCacheEnabled`, `redisCacheHost`, `redisCachePassword`, `redisCacheDatabase`, `redisCacheReadHosts`, `updateIntervalSeconds`, `metricsUpdateIntervalSeconds`, `updateMaxFailure`, CAPI scenarios. Wake with a Redis YAML change keeps the live store, WARNs those Redis fields, does not migrate memory↔Redis. AdoptTransport last-wins TLS and HTTP timeout (existing INFO `lapi transport replaced` / joiner adopted); not a mismatch WARN. `decisionScopeHeaders` stay live union (`registerLiveHeaderScopes`). Per-router stays on Bouncer (failure actions, templates, trusted IPs, Enabled, captcha). Do not fail `New`.
  By: explore

- Q: Holder middleware names as a set (like liveHeaderScopes), not ownerName.
  Decision: resolved — Client-owned registry keyed by constructor ctx → Traefik `name`, register after successful Open (OpenStream and OpenLive), unregister on ctx Done (`context.AfterFunc`), same shape as `liveHeaderScopes`. WARN prints the distinct names (a set). Two routers with the same alias are two ctxs and one name. Not a single `ownerName`. Not Peek.
  By: explore
