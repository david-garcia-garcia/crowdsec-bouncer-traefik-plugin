# LAPI connection

## Language

**transport**:
LAPI HTTP plus the request header name and the CAPI/LAPI key. Stored on Client as `atomic.Value`.
_Avoid_: `atomic.Pointer[T]`, a write-once Client `httpClient` field, CrowdsecConnection

## Overview

`package lapi` keeps construct/close in `client.go` and LAPI/CAPI HTTP in `client_http.go`. HTTP+auth lives as unexported `transport`. After `OpenStream` / `OpenLive` bind, `AdoptTransport` last-wins TLS/timeout on the same Client. Specs: `core_plugin_lapi_connection` (concurrent `AdoptTransport` last-write). Open key: `core_plugin_lapi_reclaim-key.md`.

## How to use

- Declare `transport` in `client_http.go`. Store it on Client as `atomic.Value`. Do not use `atomic.Pointer[T]` (Yaegi v0.16).
- After `OpenStream` / `OpenLive` bind, call `AdoptTransport(cfg)`: Store the new transport and idle-close the previous `*http.Client`. Last `New` wins.
- `newTransport` sets `http.Client.Timeout` and stored `httpTimeoutSeconds` from `cfg.EffectiveHTTPTimeoutSeconds(cfg.CrowdsecLapiHTTPTimeoutSeconds)`. Do not read raw `HTTPTimeoutSeconds` when the LAPI override is non-zero. Store effective seconds so `fieldsDiffer` sees a shared-default change when the override is still 0.
- Write the CAPI token on the stored transport (`getToken`). Do not keep a write-once Client key field beside it.
- Pass `defaultDecisionSeconds` into `LiveLookup`. Do not store that TTL on Client.
- After `LiveLookup`, the client-address cache key holds the `?ip=` result only. Header remediations stay on `HeaderScopeKey` via `cacheLiveScope`. Do not write the merged PreferRemediation verdict onto the IP key.
- Read a `LiveLookup` result by the remediation kind, never by the error alone: an active remediation plus a non-nil error is a decision to remediate; a non-active remediation plus a non-nil error is a LAPI failure, and the caller applies `CrowdsecLapiFailureAction`. Every query the lookup makes reports that way — the client-address query and each mapped header scope.
- One exchange over the stored transport is `core_plugin_lapi_query-round-trip.md` (drain, `401` replay, message shape). Do not restate those rules here.
- Keep `StreamStartupBlock` write-once at `startStream`. First incarnation keeps it. Do not put it on Bouncer. Do not mutate it after construct.
- Publish stream startup, healthy, and update-failure as `int64` fields with `atomic.LoadInt64` / `StoreInt64`. `StreamHealthy` loads. Do not use `atomic.Bool` or `atomic.Int64`. Intra-instance poll overlap is `core_plugin_lapi_stream-single-flight.md`.
- `logInfo` includes reclaim `sessionKey` (stream/alone `SessionKey`, live/none `Key`) and `reason` (`started|sleeping|waking|closed`). On first create, `started` INFO names process-wide stream/metrics ownership. Name transport replace and a live joiner `adopted` at INFO. Do not log `ignored` INFO for session-owned knobs (WARN is `core_plugin_lapi_reclaim-key.md`).

## Pattern snippet

```go
client.sessionKey = bindKey
replaced, err := client.AdoptTransport(cfg)
value, err := client.LiveLookup(remoteIP, scopes, defaultDecisionSeconds)
```

## Key files

- `pkg/lapi/client_http.go`
- `pkg/lapi/client.go`
- `pkg/lapi/client_live.go`
- `pkg/lapi/session.go`

## Gotchas

- After `sendQuery` returns a 2xx CAPI login body, store `login.Token` when it is non-empty. Do not require JSON `code == 200`. Official `WatcherAuthResponse` marks `code` omitempty (`ext_crowdsec_watchers_login-response`). Keep the existing `getToken statusCode:` error when the token is empty.
- A clean `?ip=` plus a remediating header writes `NoBannedValue` on the IP key. A later lookup for the same IP and a different header hits that none slot and does not inherit the first identity's ban. A header-scope query error still skips the none IP write (fail-closed).
- The IP-key TTL follows the IP query: an active `?ip=` result uses `liveCacheTTL` on that result's duration; a clean `?ip=` result uses `defaultDecisionSeconds`. Do not apply a header winner's duration to the IP key.
- Concurrent `AdoptTransport` last-writes the stored transport and idle-closes the value it replaced. No extra mutex around write-once Client scalars.
- Redis host/auth/db stay on the live/none Client Open key (`core_plugin_lapi_reclaim-key.md`). Stream Open key omits Redis and intervals; mismatch is WARN first-wins. Live/none `Key` keeps `MetricsUpdateIntervalSeconds`. Do not call `PeekLivePrefix`.
- `reclaim_put`, `reclaim_reclaim`, and `reclaim_dispose` stay DEBUG.
