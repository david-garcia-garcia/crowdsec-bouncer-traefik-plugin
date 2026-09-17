# Plugin middleware New

## Language

**LAPI Client**:
The reclaim value for one CrowdSec LAPI/CAPI decisions backend: stream/metrics tickers, LAPI HTTP, isolated cache, and in-process Range membership. Stream/alone: keyed by stream session plus remaining first-wins settings hash. Live/none: keyed by the same first-wins LAPI fields (not AppSec). Not middleware name.
_Avoid_: CrowdsecConnection, AppSec client, Bouncer, Plugin, process singleton, `sync.Once`

**AppSec Client**:
The reclaim value for one CrowdSec AppSec listener: replaceable HTTP+auth, host, body limit. Keyed by AppSec URL+key+body limit. Last `New` adopts TLS/timeout. Not the LAPI Client.
_Avoid_: CrowdsecConnection, LAPI, `AppsecQuery` on the LAPI type, `atomic.Pointer[T]`

**Stream session**:
The CrowdSec bouncer row this process polls: LAPI scheme, host, and path plus lapiKey (CAPI machine and password in alone). Settings such as metrics interval are not the session; `PeekLivePrefix` finds a live sibling on that stem.
_Avoid_: middleware name, IdentityHex, `scopes=`, AppSec host

**Bouncer**:
The per-router `http.Handler` Traefik gets back from `New`. Holds `next`, request policy (trusted IPs, ban/captcha, Enabled, AppSec-on-pass, LAPI failure action, Redis fail-closed, live-cache TTL), `lapiClient` (`*lapi.Client`, nil in `crowdsecMode: appsec`), and `appsecClient` (`*appsec.Client`, nil when AppSec is off).
_Avoid_: ForRoute, Plugin core, the reclaim value

**Failure action**:
The operator enum (`passthrough` | `ban` | `captcha`) this plugin applies when LAPI or AppSec does not return a usable verdict. LAPI action is per-router on Bouncer; AppSec action is per-router on Bouncer. Default is `ban`.
_Avoid_: fail mode, FailMode, the three removed AppSec block bools, AppSec JSON `action: captcha`, LAPI Client identity

## Overview

Traefik Yaegi loads `CreateConfig` and `New` from the module-root package. `New` must use the constructor `ctx` as the reclaim holder. Do not change `.traefik.yml` `import`.

## How to use

- Keep `CreateConfig` / `New` on the module root (`plugin.go`).
- Keep `pluginVersion` in root `version.go` (release workflow bumps it). Pass it into `lapi.New` and `appsec.New`.
- Call `lapi.Prepare` then `appsec.Prepare`. Stream/alone: `lapi.OpenStream`. Live/none: `lapi.OpenLive`. `crowdsecMode: appsec`: skip LAPI Open. When `crowdsecAppsecEnabled`: `appsec.Open` (`AdoptTransport` inside). Return `bouncer.New(..., lapiClient, appsecClient, ...)`.
- Put stream tickers, replaceable LAPI HTTP (`transport` on `atomic.Value`), cache, and Range membership on `lapi.Client`. Put AppSec HTTP+auth (`transport` on `atomic.Value`) on `appsec.Client`. Put captcha, templates, LAPI failure action, Redis fail-closed, and live-cache TTL on Bouncer. After `OpenStream` / `OpenLive`, `AdoptTransport` last-wins LAPI TLS/timeout. After `appsec.Open`, last `New` last-wins AppSec TLS/timeout.
- Pass `config.DefaultDecisionSeconds` into `LiveLookup`. Two routers on one Client last-write that TTL into the shared live cache.
- Keep `StreamStartupBlock` write-once at `startStream`. First incarnation keeps it. Do not put it on Bouncer.
- Resolve client IP with `pkg/ip.GetRemoteIP`. Fold `remoteIP`, parsed `net.IP`, and `ipType` into `clientRequest`. Keep the name `req`. Do not parse `RemoteAddr` on LAPI or AppSec. Do not put scopes or origin on that type.
- Range and header-mapped CrowdSec scopes live in `pkg/decisionscope`. Do not geolocate in `New` or `ServeHTTP`.
- Live LAPI error and stream-unhealthy cache miss use `crowdsecLapiFailureAction`. Cache hits still apply when the stream is unhealthy. `passthrough` uses the pass path (AppSec still runs if enabled).
- Watch logs `reclaim_put|bind|orphan|reclaim|dispose`.

## Pattern snippet

```go
if config.CrowdsecMode == configuration.StreamMode || config.CrowdsecMode == configuration.AloneMode {
	lapiClient, err := lapi.OpenStream(ctx, config, log, name, pluginVersion)
	return bouncer.New(next, name, config, lapiClient, appsecClient, log)
}
if config.CrowdsecMode != configuration.AppsecMode {
	lapiClient, err := lapi.OpenLive(ctx, config, log, name, pluginVersion)
	return bouncer.New(next, name, config, lapiClient, appsecClient, log)
}
return bouncer.New(next, name, config, nil, appsecClient, log)
```

## Key files

- `plugin.go`
- `pkg/lapi/`
- `pkg/lapi/client_http.go`
- `pkg/lapi/client_live.go`
- `pkg/appsec/`
- `pkg/bouncer/bouncer.go`
- `pkg/bouncer/clientrequest.go`
- `.traefik.yml`

## Gotchas

- Do not put middleware name, `next`, ban/captcha templates, trusted IPs, Enabled, AppSec knobs, LAPI failure action, Redis fail-closed, live-cache TTL, `StreamStartupBlock`, HTTP timeout, or LAPI TLS in the LAPI reclaim key. Do not put AppSec TLS or HTTP timeout in the AppSec reclaim key.
- `crowdsecLapiFailureAction` is per-router on Bouncer. `crowdsecAppsecFailureAction` stays on Bouncer. Two routers on one Client MAY disagree.
- Stream/alone: CrowdSec stores one `GET /v1/decisions/stream` cursor per hashed API key plus the IP LAPI sees (this process’s outbound address). Reclaim `Open` key is session prefix plus a hash of remaining first-wins settings (intervals, Redis host/auth/db, `updateMaxFailure`, CAPI scenarios, `decisionScopeHeaders`). A second live middleware on the same LAPI URL+key with a different remaining hash is warn-and-wire via `PeekLivePrefix` (first New wins those knobs; INFO `ignored`). A reload that only changes dropped knobs reuses the Client; last New `AdoptTransport`s TLS/timeout (INFO `adopted`). Last holder Sleeps tickers; reload with the same snapshot Wakes (`startup=false`); a new remaining snapshot Opens a new key and the sleeper dies on grace. Isolated backends need a second bouncer key. Live/none split on the same first-wins LAPI identity (AppSec excluded).
- LAPI `Close()` stops tickers, idle LAPI HTTP, and the cache Redis pool. AppSec `Close()` releases idle AppSec HTTP. Do not use `sync.Once`.
- Both puts use `Open` / `OpenWithHooks` on the process table (`ProcessGrace` 30s). Utilities `DefaultGrace` (10s) is only the table’s negative-grace fallback.
- Lifecycle INFO lines include reclaim `sessionKey` and `reason` (`started|sleeping|waking|closed`). Stream health transitions: `crowdsec stream became unhealthy|healthy` (not every poll). INFO also names `lapi transport replaced` and a live joiner `ignored` vs `adopted`. `reclaim_put`, `reclaim_reclaim`, and `reclaim_dispose` stay DEBUG. Cache tick messages `handleStreamCache:updated` and `handleStreamCache:alreadyUpdated` are DEBUG.
