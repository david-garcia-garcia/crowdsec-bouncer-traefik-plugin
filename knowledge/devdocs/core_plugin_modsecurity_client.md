# ModSecurity Client

## Language

**ModSec Client**:
The reclaim value for one OWASP CRS sidecar inspect listener (`pkg/modsecurity`). Opened by ownership key (middleware name plus `modsecUrl`, `modsecHttpTimeoutSeconds`, `modsecBodyLimit`, `modsecDenyVerbsWithBody`, and the unhealthy-backoff knobs). Owns sidecar HTTP, the body pool, deny-verbs, and the admission gate. Not the AppSec Client and not CrowdSec AppSec JSON.
_Avoid_: AppSec client, `modSecurityUrl`, FailMode as ownership, `atomic.Pointer[T]`, `X-Crowdsec-Appsec-*`

**Admission gate**:
The utilities `backendbackoff.Gate` on a WAF Client when that Client's unhealthy-backoff period is greater than zero. One Gate per Client. This plugin must not copy that package. Jitter and TTL stay unset (partial Config disables jitter).
_Avoid_: FailureAction, FailMode, copying Gate into this repository, a public unused window knob

## Overview

`modsecurity.Open` reclaims one CRS sidecar Client. Inspect protocol lives on `core_plugin_modsecurity_inspect.md`. Constructor wiring: `core_plugin_middleware.md`. Slots: `core_plugin_middleware_instance-slots.md`. Spec: `core_plugin_modsecurity_client`.

## How to use

- Keep the type in `pkg/modsecurity`. Do not import `pkg/appsec` or `pkg/lapi`. Do not speak CrowdSec AppSec JSON.
- Call `modsecurity.Prepare` from `New` after captcha Prepare. When `modsecEnabled` is true and `modsecInstanceName` is empty after trim, fill it to the Traefik name. When the flag is false, leave an empty name empty.
- Open with `modsecurity.Open` (reclaim by `OwnershipKey`). A knob change is a new Client. Two middleware names with the same `modsecUrl` are two Clients.
- Hash `OwnershipKey` from middleware name plus `modsecUrl`, timeout, body limit, deny-verbs-with-body, and the four unhealthy-backoff knobs. Slot name, `bouncerEnabled`, bounce knobs, LAPI, AppSec, captcha, and per-router `bouncerModsecFailMode` stay off it.
- When `modsecUnhealthyBackOffPeriodSecs` is greater than 0, build one `backendbackoff.Gate` from dest utilities `v1.0.7`. Period `0` or omitted builds no gate (default `0`). Omitted threshold is `5`. Omitted ratio is packaged `0.30`. Omitted max period equals the base period. Do not set `Jitter` or `TTL`.
- Omitted or nil `modsecDenyVerbsWithBody` is `HEAD`, `GET`, `DELETE`, `OPTIONS`, `TRACE`, `CONNECT`. An explicit empty list denies nothing. A listed method with a readable body byte is HTTP 400, does not call the sidecar, and does not call `next`, including after the gate has tripped.
- Omitted `modsecBodyLimit` is 8388608 (8 MiB). `0` is unlimited. A positive limit caps the inbound copy; exceeding it is HTTP 413 and does not call the sidecar.
- `newHTTPClient` sets `Timeout` from `modsecHttpTimeoutSeconds` (default 10) and `CheckRedirect` so a sidecar 3xx is a copied block (`http.ErrUseLastResponse`).
- `Close` Closes a non-nil Gate and idle sidecar HTTP. Safe to call more than once. Sleep/Wake only log; ModSec has no tickers.

## Pattern snippet

```go
if err := modsecurity.Prepare(&config, log, name); err != nil {
	return nil, err
}
client, err := modsecurity.Open(bindCtx, &config, log, name, pluginVersion)
if err != nil {
	return nil, err
}
err = reclaim.SetAlias(modsecurity.OwnershipKey(&config, name), instanceAlias("modsec", config.ModsecInstanceName), name, "modsec")
```

## Key files

- `pkg/modsecurity/client.go`
- `pkg/modsecurity/session.go` (`OwnershipKey`, `Prepare`, `Open`)
- `pkg/modsecurity/gate.go`
- `pkg/modsecurity/client_http.go`
- `pkg/modsecurity/body.go`
- `pkg/configuration/configuration.go` (`modsec*` knobs)
- `plugin.go`

## Gotchas

- Traefik decode drops source-plugin `modSecurityUrl`. The Config field is `modsecUrl`.
- Default ModSec backoff is off (`0`). Default AppSec backoff is 30. Do not copy the AppSec default onto ModSec.
- FailMode is per-router on Bouncer. Two routers on one published Client MAY disagree. It is not in the ownership key.
- Do not put a second slot table or `atomic.Pointer[T]` on this Client.
