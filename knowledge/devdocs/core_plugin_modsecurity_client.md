# ModSecurity Client

## Language

**ModSec Client**:
The reclaim value for one OWASP CRS sidecar inspect listener (`pkg/modsecurity`). Opened by ownership key (middleware name plus `modsecUrl`, `modsecHttpTimeoutSeconds`, `modsecBodyLimit`, and `modsecUnhealthyBackOffPeriodSecs`). Owns sidecar HTTP and the admission gate. Body buffering is `pkg/wafhop` (no pool). Not the AppSec Client and not CrowdSec AppSec JSON.
_Avoid_: AppSec client, `modSecurityUrl`, the failure action as ownership, `atomic.Pointer[T]`, `X-Crowdsec-Appsec-*`

**Admission gate**:
The `pkg/admission` wrapper around the utilities `backendbackoff.Gate`, on a WAF Client when that Client's unhealthy-backoff period is greater than zero. One Gate per Client. The trip rule is fixed (`admission.TripFailures` 5, `admission.FailureRatio` 0.30) and the cooldown is the period, with no growth. This plugin must not copy the utilities package. Jitter and TTL stay unset (partial Config disables jitter).
_Avoid_: failure action, copying Gate into this repository, a ratio, threshold, or max-period knob

## Overview

`modsecurity.Open` reclaims one CRS sidecar Client. Inspect protocol lives on `core_plugin_modsecurity_inspect.md`. Constructor wiring: `core_plugin_middleware.md`. Slots: `core_plugin_middleware_instance-slots.md`. Spec: `core_plugin_modsecurity_client`.

## How to use

- Keep the type in `pkg/modsecurity`. Do not import `pkg/appsec` or `pkg/lapi`. Do not speak CrowdSec AppSec JSON.
- Call `modsecurity.Prepare` from `New` after captcha Prepare. When `modsecEnabled` is true and `modsecInstanceName` is empty after trim, fill it to the Traefik name. When the flag is false, leave an empty name empty.
- Open with `modsecurity.Open` (reclaim by `OwnershipKey`). A knob change is a new Client. Two middleware names with the same `modsecUrl` are two Clients.
- Hash `OwnershipKey` from middleware name plus `modsecUrl`, timeout, body limit, and `modsecUnhealthyBackOffPeriodSecs`. Slot name, `bouncerEnabled`, bounce knobs, LAPI, AppSec, captcha, and per-router `bouncerModsecFailureAction` stay off it.
- When `modsecUnhealthyBackOffPeriodSecs` is greater than 0, `admission.New` builds one gate on `backendbackoff.Gate` from utilities `v1.0.12`. `Allow` returns a `Permit` and takes no context, so `Gate.Admit` checks the request context itself; `Report` takes that `Permit`. A stale permit's report is ignored and does not log the healthy line. Period `0` or omitted builds no gate (default `0`). The period is the only knob: each failure spends 1 of a budget of 5, each success earns back `0.30/0.70`, so 5 failures in a row trip. Max cooldown equals the base. Do not set `Jitter` or `TTL`.
- The gate logs WARN `crowdsec modsec backoff started` once on the first skipped request, and INFO `crowdsec modsec backoff ended` once when a probe's report is applied. A stale permit's report does not log that line.
- Omitted `modsecBodyLimit` is 8388608 (8 MiB). There is no unlimited value: with `modsecEnabled`, a limit below 1 fails `New` (`validateModsecURL`). A middleware that does not own ModSec does not validate it. Exceeding the limit is HTTP 413 and does not call the sidecar.
- There is no method list for bodies (`modsecDenyVerbsWithBody` is gone). A readable body on any method goes to the sidecar; CRS 920170/920171 block a body on GET/HEAD. An operator who wants more adds a `SecRule` to the sidecar.
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
- `pkg/modsecurity/client_http.go`
- `pkg/admission/admission.go` (gate wrapper, `TripFailures`, `FailureRatio`)
- `pkg/wafhop/body.go` (shared body rules)
- `pkg/configuration/configuration.go` (`modsec*` knobs)
- `plugin.go`
- `examples/modsecurity/` (runnable example, `make run_modsecurity`; operator docs: `docs/modsecurity.md`, failure handling in `docs/failure-modes.md`)

## Gotchas

- Traefik decode drops source-plugin `modSecurityUrl`. The Config field is `modsecUrl`.
- Default ModSec backoff is off (`0`). Default AppSec backoff is 30. Do not copy the AppSec default onto ModSec.
- The failure action is per-router on Bouncer. Two routers on one published Client MAY disagree. It is not in the ownership key.
- Do not put a second slot table or `atomic.Pointer[T]` on this Client.
