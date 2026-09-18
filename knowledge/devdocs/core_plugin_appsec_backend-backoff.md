# AppSec backendbackoff Gate

## Language

**backendbackoff Gate**:
The published Allow/Report/Close admission object from `traefik-middleware-utilities/backendbackoff`. One lives on an `appsec.Client`.
_Avoid_: Tracker, `pkg/health`, traefik-modsecurity, client-address key, LAPI Gate

**backend URL stem**:
Scheme + host + path the AppSec Client already composes for the listener attempt. Allow/Report key.
_Avoid_: reclaim key, client address, inbound request URL

## Overview

AppSec `Query` admits each `Do` through that Gate so a dead listener is not contacted on every request. Spec: `core_plugin_appsec_backend-backoff`. Envelope parse and challenge relay stay `core_plugin_appsec.md`. FailureAction enums stay `core_plugin_appsec_failure-action`.

## How to use

- Import `github.com/david-garcia-garcia/traefik-middleware-utilities/backendbackoff`. Vendor it. Stay on `v1.0.3`. Do not copy the package into `pkg/`.
- Construct the Gate in `appsec.New` from `configuration.BackendBackoffConfig()`.
- Call `Allow(httpReq.Context(), stem)` after the outbound request exists and before `Do`. Stem is `scheme` + `host` + `path`. Do not sleep on wait; Debug-log it.
- Inbound unreadable body that never `Do`s: no Allow, no Report; today's FailureAction stays.
- Denied or Allow-error: `resultForFailureAction` with a skip message that is not `unreachable`.
- After an admitted `Do`, `Report(stem, success)`. Failure is Do error, 502/503/504, or HTTP 500. Response-body io, parse, 200/403, and oversized-body Report success.
- `Close` the Gate from `appsec.Client.Close`.
- Do not put backoff knobs on the AppSec reclaim key. Last `New` still `AdoptTransport`s TLS/timeout.
- Reuse the `ip` argument on `X-Crowdsec-Appsec-Ip`. Reuse inbound `Host` on the existing header copy.

## Pattern snippet

```go
ok, wait, err := c.gate.Allow(httpReq.Context(), stem)
if err != nil || !ok {
	c.log.Debug("appsecQuery:skipped", "wait", wait)
	return resultForFailureAction(pol.FailureAction, "appsecQuery:skipped")
}
res, err := current.httpClient.Do(req)
```

## Key files

- `pkg/appsec/client.go`
- `pkg/appsec/query.go`
- `pkg/configuration/configuration.go`

## Gotchas

- `errAppsecReadBody` after an admitted Do Reports success and still uses FailureAction.
- Unreadable-body passthrough still Does a headers-only GET — that GET is admitted.
- Client address stays `pkg/ip.GetRemoteIP`. Do not parse `RemoteAddr`.
