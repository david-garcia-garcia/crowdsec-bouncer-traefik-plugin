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

**Prepared snapshot**:
A copy of Traefik’s `*configuration.Config` that `New` mutates (log level, path aliases, Prepare). Reclaim identity and Crowdsec connection construction use this copy.
_Avoid_: Traefik’s live Config pointer, Prepared type

## Overview

Traefik Yaegi loads `CreateConfig` and `New` from the module-root package. `New` must use the constructor `ctx` as the reclaim holder. Do not change `.traefik.yml` `import`.

## How to use

- Keep `CreateConfig` / `New` on the module root (`plugin.go`).
- Keep `pluginVersion` in root `version.go` (release workflow bumps it). Pass it into `crowdsecconnection.New`.
- Copy Traefik’s `*configuration.Config` before any write. Call `crowdsecconnection.Prepare` then `reclaim.Open(ctx, crowdsecconnection.Key(&prepared), log, create)` on that snapshot. Do not assign through Yaegi’s pointer.
- Type-assert the stored value to `*crowdsecconnection.CrowdsecConnection` and return `bouncer.New(...)`.
- Put stream tickers, LAPI HTTP, cache, and Range membership on CrowdsecConnection. Put captcha and templates on Bouncer.
- Resolve client IP with `pkg/ip.GetRemoteIP`. Do not parse `RemoteAddr` on the connection.
- Range and header-mapped CrowdSec scopes live in `pkg/decisionscope`. Do not geolocate in `New` or `ServeHTTP`.
- Live LAPI error and stream-unhealthy cache miss use `crowdsecLapiFailureAction`. Cache hits still apply when the stream is unhealthy. `passthrough` uses the pass path (AppSec still runs if enabled).
- Watch logs `reclaim_put|bind|orphan|reclaim|dispose`.

## Pattern snippet

```go
prepared := *config
// LogLevel / path aliases / Prepare mutate prepared only.
stored, err := reclaim.Open(ctx, crowdsecconnection.Key(&prepared), log, func() (any, error) {
	return crowdsecconnection.New(&prepared, log, pluginVersion)
})
conn := stored.(*crowdsecconnection.CrowdsecConnection)
return bouncer.New(next, name, &prepared, conn, log)
```

## Key files

- `plugin.go`
- `pkg/crowdsecconnection/`
- `pkg/bouncer/bouncer.go`
- `.traefik.yml`

## Gotchas

- Do not put middleware name, `next`, ban/captcha templates, trusted IPs, or Enabled in the reclaim key.
- Do not write Traefik’s Config pointer in `New` (LogLevel, path aliases, Prepare). Identity hashes the snapshot.
- `crowdsecLapiFailureAction` is on CrowdsecConnection identity (shared with `updateMaxFailure`). `crowdsecAppsecFailureAction` stays on Bouncer.
- Same connection fields share one ticker; different LAPI/mode/redis/interval are two Connections in one Traefik.
- `Close()` stops tickers, idle LAPI/AppSec HTTP, and the cache Redis pool when no constructor ctx remains and grace elapses. Do not use `sync.Once`.
