# Plugin middleware New

## Language

**LAPI Client**:
The reclaim value for one CrowdSec LAPI/CAPI decisions backend: stream/metrics tickers, LAPI HTTP, a reclaimed DecisionStore, and in-process Range membership. Stream/alone: keyed by cursor SessionHex plus Redis store params (`lapi:stream:`). Live/none: keyed by SessionHex plus a hash of Redis store params and `MetricsUpdateIntervalSeconds` (`lapi:`). Not middleware name. `IdentityHex` is not the live Open suffix.
_Avoid_: CrowdsecConnection, AppSec client, Bouncer, Plugin, process singleton, `sync.Once`, first-wins settings hash, PeekLivePrefix

**AppSec Client**:
The reclaim value for one CrowdSec AppSec listener: replaceable HTTP+auth, host, body limit. Keyed by AppSec URL+key+body limit. Last `New` adopts TLS/timeout. Not the LAPI Client.
_Avoid_: CrowdsecConnection, LAPI, `AppsecQuery` on the LAPI type, `atomic.Pointer[T]`

**Stream session**:
The CrowdSec bouncer row this process polls: LAPI scheme, host, and path plus lapiKey (CAPI machine and password in alone). Settings such as metrics interval are not the session. A live joiner `Open`s the same cursor-plus-Redis key.
_Avoid_: middleware name, IdentityHex as the Open suffix, `scopes=`, AppSec host, PeekLivePrefix

**Bouncer**:
The per-router `http.Handler` Traefik gets back from `New`. Holds `next`, request policy (trusted IPs, ban/captcha, Enabled, AppSec-on-pass, LAPI failure action, Redis fail-closed, live-cache TTL), `lapiClient` (`*lapi.Client`, nil in `crowdsecMode: appsec`), and `appsecClient` (`*appsec.Client`, nil when AppSec is off).
_Avoid_: ForRoute, Plugin core, the reclaim value

**Failure action**:
The operator enum (`passthrough` | `ban` | `captcha`) this plugin applies when LAPI or AppSec does not return a usable verdict. LAPI action is per-router on Bouncer; AppSec action is per-router on Bouncer. Default is `ban`.
_Avoid_: fail mode, FailMode, the three removed AppSec block bools, AppSec JSON `action: captcha`, LAPI Client identity

## Overview

Traefik Yaegi loads `CreateConfig` and `New` from the module-root package. `New` must use the constructor `ctx` as the reclaim holder. Do not change `.traefik.yml` `import`. Specs: `core_plugin_middleware_bouncer` (Yaegi `New` / Bouncer). Open key: `core_plugin_lapi_reclaim-key.md`.

## How to use

- Keep `CreateConfig` / `New` on the module root (`plugin.go`).
- Keep `pluginVersion` in root `version.go` (release workflow bumps it). Pass it into `lapi.New` and `appsec.New`.
- Call `lapi.Prepare` then `appsec.Prepare`. Stream/alone: `lapi.OpenStream` (registers this `New` ctx on the live-router scope union). Live/none: `lapi.OpenLive`. `crowdsecMode: appsec`: skip LAPI Open. When `crowdsecAppsecEnabled`: `appsec.Open` (`AdoptTransport` inside). Return `bouncer.New(..., lapiClient, appsecClient, ...)`. Open key: `core_plugin_lapi_reclaim-key.md`. Stream `scopes=`: `core_plugin_lapi_scope-union.md`.
- Put stream tickers, replaceable LAPI HTTP (`transport` on `atomic.Value`), and Range membership on `lapi.Client`. Open the DecisionStore on the same `New` ctx (`core_cache_client.md`). Put AppSec HTTP+auth (`transport` on `atomic.Value`) on `appsec.Client`. Put captcha, templates, LAPI failure action, Redis fail-closed, and live-cache TTL on Bouncer. After `OpenStream` / `OpenLive`, `AdoptTransport` last-wins LAPI TLS/timeout. After `appsec.Open`, last `New` last-wins AppSec TLS/timeout.
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
- Stream/alone: CrowdSec stores one `GET /v1/decisions/stream` cursor per hashed API key plus the IP LAPI sees (this process’s outbound address). Reclaim `Open` key is `lapi:stream:` plus SessionHex plus Redis store params. A second stream `New` on the same cursor plus Redis `Open`s that key. Interval, CAPI scenario, `updateMaxFailure`, and header-map mismatch is silent first-wins for those create-time scalars. Do not call `Peek` / `PeekLivePrefix`. Last New `AdoptTransport`s TLS/timeout (INFO `adopted`). Last holder Sleeps tickers; reload with the same Redis snapshot Wakes (`startup=false`); a different Redis host Opens a new key and the sleeper dies on grace. Isolated backends need a second bouncer key. Live/none `Key` is `lapi:` plus SessionHex plus Redis and `MetricsUpdateIntervalSeconds` (AppSec excluded). `IdentityHex` is not the live Open suffix.
- LAPI `Close()` stops tickers and idle LAPI HTTP. It does not Close the shared DecisionStore. AppSec `Close()` releases idle AppSec HTTP. Do not use `sync.Once`.
- Both puts use `Open` / `OpenWithHooks` on the process table (`ProcessGrace` 30s). Utilities `DefaultGrace` (10s) is only the table’s negative-grace fallback.
- Lifecycle INFO lines include reclaim `sessionKey` and `reason` (`started|sleeping|waking|closed`). Stream health transitions: `crowdsec stream became unhealthy|healthy` (not every poll). INFO also names `lapi transport replaced` and a live joiner `adopted` (no `ignored` / warn-and-wire). `reclaim_put`, `reclaim_reclaim`, and `reclaim_dispose` stay DEBUG. Cache tick messages `handleStreamCache:updated` and `handleStreamCache:alreadyUpdated` are DEBUG.
