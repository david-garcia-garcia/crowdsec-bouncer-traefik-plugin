# Plugin middleware New

## Language

**CrowdsecConnection**:
The reclaim value for one Crowdsec backend: stream/metrics tickers, LAPI/CAPI HTTP, AppSec client, and an isolated cache. Keyed by connection fields, not middleware name.
_Avoid_: Bouncer, Plugin, process singleton, `sync.Once`

**Bouncer**:
The per-router `http.Handler` Traefik gets back from `New`. Holds `next`, request policy (trusted IPs, ban/captcha, Enabled, AppSec-on-pass), and a pointer to the reclaimed CrowdsecConnection.
_Avoid_: ForRoute, Plugin core, the reclaim value

## Overview

Traefik Yaegi loads `CreateConfig` and `New` from the module-root package. `New` must use the constructor `ctx` as the reclaim holder. Do not change `.traefik.yml` `import`.

## How to use

- Keep `CreateConfig` / `New` on the module root (`plugin.go`).
- Keep `pluginVersion` in root `version.go` (release workflow bumps it). Pass it into `crowdsecconnection.New`.
- Call `crowdsecconnection.Prepare` then `reclaim.Open(ctx, crowdsecconnection.Key(config), log, create)`.
- Type-assert the stored value to `*crowdsecconnection.CrowdsecConnection` and return `bouncer.New(...)`.
- Put stream tickers, LAPI HTTP, and cache on CrowdsecConnection. Put captcha and templates on Bouncer.
- Resolve client IP with `pkg/ip.GetRemoteIP`. Do not parse `RemoteAddr` on the connection.
- Range and header-mapped CrowdSec scopes live in `pkg/decisionscope`. Do not geolocate in `New` or `ServeHTTP`.
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
- `pkg/bouncer/bouncer.go`
- `.traefik.yml`

## Gotchas

- Do not put middleware name, `next`, ban/captcha templates, trusted IPs, or Enabled in the reclaim key.
- Same connection fields share one ticker; different LAPI/mode/redis/interval are two Connections in one Traefik.
- `Close()` stops tickers, idle LAPI/AppSec HTTP, and the cache Redis pool when no constructor ctx remains and grace elapses. Do not use `sync.Once`.
