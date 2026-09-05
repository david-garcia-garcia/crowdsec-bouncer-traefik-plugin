# Plugin middleware New

## Language

**CrowdsecConnection**:
The reclaim value for one Crowdsec backend: stream/metrics tickers, LAPI/CAPI HTTP, AppSec client, an isolated cache, and in-process Range membership. Keyed by connection fields, not middleware name.
_Avoid_: Bouncer, Plugin, process singleton, `sync.Once`

**Bouncer**:
The per-router `http.Handler` Traefik gets back from `New`. Holds `next`, request policy (trusted IPs, ban/captcha, Enabled, AppSec-on-pass), and a pointer to the reclaimed CrowdsecConnection.
_Avoid_: ForRoute, Plugin core, the reclaim value

**Failure action**:
The operator enum (`passthrough` | `ban` | `captcha`) this plugin applies when LAPI or AppSec does not return a usable verdict. LAPI action is on CrowdsecConnection identity; AppSec action is per-router on Bouncer. Default is `ban`.
_Avoid_: fail mode, FailMode, the three removed AppSec block bools, AppSec JSON `action: captcha`

## Overview

Traefik Yaegi loads `CreateConfig` and `New` from the module-root package. `New` must use the constructor `ctx` as the reclaim holder. Do not change `.traefik.yml` `import`.

## How to use

- Keep `CreateConfig` / `New` on the module root (`plugin.go`).
- Keep `pluginVersion` in root `version.go` (release workflow bumps it). Pass it into `crowdsecconnection.New`.
- Call `crowdsecconnection.Prepare` then `reclaim.Open(ctx, crowdsecconnection.Key(config), log, create)`.
- Type-assert the stored value to `*crowdsecconnection.CrowdsecConnection` and return `bouncer.New(...)`.
- Put stream tickers, LAPI HTTP, cache, and Range membership on CrowdsecConnection. Put captcha and templates on Bouncer.
- Build LAPI and AppSec `tls.Config` in `pkg/crowdsecconnection` next to those HTTP clients. Keep the Config DTO, file secrets, templates, and validation in `pkg/configuration` sibling files (`config.go`, `secrets.go`, `template.go`, `validate.go`).
- Resolve client IP with `pkg/ip.GetRemoteIP`. Do not parse `RemoteAddr` on the connection.
- Range and header-mapped CrowdSec scopes live in `pkg/decisionscope`. Do not geolocate in `New` or `ServeHTTP`.
- Live LAPI error and stream-unhealthy cache miss use `crowdsecLapiFailureAction`. Cache hits still apply when the stream is unhealthy. `passthrough` uses the pass path (AppSec still runs if enabled).
- Watch logs `reclaim_put|bind|orphan|reclaim|dispose`.

## Pattern snippet

```go
stored, err := reclaim.Open(ctx, crowdsecconnection.Key(config), log, func() (any, error) {
	return crowdsecconnection.New(config, log, pluginVersion)
})
conn := stored.(*crowdsecconnection.CrowdsecConnection)
return bouncer.New(next, name, config, conn, log)
```

## Key files

- `plugin.go`
- `pkg/crowdsecconnection/`
- `pkg/configuration/`
- `pkg/bouncer/bouncer.go`
- `.traefik.yml`

## Gotchas

- Do not put middleware name, `next`, ban/captcha templates, trusted IPs, or Enabled in the reclaim key.
- `crowdsecLapiFailureAction` is on CrowdsecConnection identity (shared with `updateMaxFailure`). `crowdsecAppsecFailureAction` stays on Bouncer.
- Same connection fields share one ticker; different LAPI/mode/redis/interval are two Connections in one Traefik.
- `Close()` stops tickers, idle LAPI/AppSec HTTP, and the cache Redis pool when no constructor ctx remains and grace elapses. Do not use `sync.Once`.
