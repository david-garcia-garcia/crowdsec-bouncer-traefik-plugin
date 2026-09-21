# Explore
IssueKey: 2026-09-05-split-connection-files

## Concepts

`CrowdsecConnection` is the reclaim value: one LAPI/CAPI identity, stream and metrics tickers, isolated cache, in-process Range membership, AppSec HTTP client. Callers (`plugin.go` `Prepare`/`New`, `pkg/bouncer` `LiveLookup`/`AppsecQuery`/`Cache`/`RangeMembership`) talk to the type, not a file.

```
pkg/crowdsecconnection/  (one package)
┌─────────────────────────────────────────────────────────┐
│ connection.go        type, Prepare, New, Close,         │
│                      accessors, range membership,       │
│                      startTicker/stopTicker             │
├──────────────┬──────────────┬──────────────┬────────────┤
│ _appsec.go   │ _stream.go   │ _live.go     │ _http.go   │
│ AppsecQuery  │ startStream  │ LiveLookup   │ crowdsec   │
│ + helpers    │ handleStream │ handleNo     │ Query,     │
│              │ Cache        │ StreamCache  │ getToken   │
├──────────────┴──────────────┴──────────────┴────────────┤
│ _metrics.go  reportMetrics                              │
│ identity.go  Key / IdentityHex   (do not touch)         │
│ connection_decisions.go  stream store/query live parse  │
└─────────────────────────────────────────────────────────┘
```

This is a physical split inside the existing package, matching `identity.go` and `connection_decisions.go`. Not `pkg/appsec`. Not a reclaim or `sync.Once` change. Client IP stays `pkg/ip.GetRemoteIP`. Connection reclaim identity stays `identity.go`.

No third-party Crowdsec protocol change. Existing usage packets (`core_plugin_middleware.md`, `core_plugin_appsec.md`, `core_plugin_decisionscope.md`) still describe the type correctly; they cite `connection.go` as a key file and will need path notes after the split (devdocs impact).

## Decisions

- Same package `crowdsecconnection`. Same exported API. Move functions; do not rewrite them.
- `connection.go` keeps the type, `Prepare`, `New`, `Close`, accessors (`Cache`, `RangeMembership`, `Mode`, `StreamHealthy`, `LapiFailureAction`, `RedisUnreachableBlock`, `StreamFetches`, `IncBlocked`), range hydrate/store, `Decision` DTO, `startTicker`/`stopTicker`.
- New files own the jobs named in the ticket (see Open questions for leftovers).
- Tests stay in the same package; they keep compiling without import changes.
- Do not edit `identity.go`, `plugin.go`, `configuration.go`, `pkg/ip`, cache constants, or `GetTLSConfigCrowdsec`.

## Open questions

- Q: Where do `startTicker` and `stopTicker` live?
  Decision: resolved — keep in `connection.go` next to `New`/`Close`; both stream and metrics tickers use them.
  By: explore

- Q: Where does `closeIdle` live?
  Decision: resolved — `connection_http.go`; `Close` still calls it.
  By: explore

- Q: Where do exported DTOs live (`Decision`, `Stream`, `Login`, `AppsecResponse`, `AppsecPolicy`)?
  Decision: assumed — `Decision` stays in `connection.go` (used by stream, live, and `connection_decisions.go`). `Stream` moves with stream. `Login` moves with HTTP. `AppsecResponse`/`AppsecPolicy`/`ErrFailureCaptcha`/`AppsecAction*` move with AppSec.
  By: explore

- Q: Where do route/header constants live?
  Decision: assumed — AppSec header constants in `connection_appsec.go`. LAPI/CAPI host/header/route constants in `connection_http.go` (already referenced from `connection_decisions.go` in the same package). `cacheTimeoutKey` in `connection_stream.go`.
  By: explore

- Q: Does this work set or reconstruct client identity (address, Host, trust hop)?
  Decision: resolved — no. Client IP stays `pkg/ip.GetRemoteIP`. Reclaim identity stays `identity.go` (out of scope).
  By: explore

- Q: New package vs file split?
  Decision: resolved — file split only. `pkg/appsec` is out of scope.
  By: explore
