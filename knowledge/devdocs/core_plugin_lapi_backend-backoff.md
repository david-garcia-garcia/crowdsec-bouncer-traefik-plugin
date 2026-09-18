# LAPI backendbackoff Gate

## Language

**backendbackoff Gate**:
The published Allow/Report/Close admission object from `traefik-middleware-utilities/backendbackoff`. One lives on a live/none `lapi.Client`. Stream/alone LAPI has none.
_Avoid_: Tracker, `pkg/health`, traefik-modsecurity, client-address key

**backend URL stem**:
Scheme + host + path the Client already composes for the LAPI HTTP attempt (decisions route, no query). Allow/Report key.
_Avoid_: reclaim key, client address, hashed identity

## Overview

Live/none LAPI admits each GET through that Gate so a dead LAPI is not contacted on every request. Spec: `core_plugin_lapi_backend-backoff`. Stream polls stay on `UpdateMaxFailure` (`core_plugin_lapi_connection.md`). FailureAction after a skip is `core_plugin_lapi_failure-action`.

## How to use

- Import `github.com/david-garcia-garcia/traefik-middleware-utilities/backendbackoff`. Vendor it. Stay on `v1.0.3`. Do not copy the package into `pkg/`.
- Construct the Gate in live/none `lapi.New` from `configuration.BackendBackoffConfig()`. Stream/alone leave it nil.
- Call `Allow(req.Context(), stem)` before each `queryLiveDecisions` GET. Stem is `scheme` + `host` + `path` without `RawQuery`. Do not use constructor ctx or `context.Background()`. Do not sleep on wait; Debug-log it.
- Denied or Allow-error: return a skip error that is not `unreachable` or `banned`. Existing fail-closed / active-ban-outranks stay.
- After an admitted GET, `Report(stem, success)`. Success is HTTP+parse that yielded ban, captcha, or none. Failure is query/HTTP/parse/duration-parse.
- `Close` the Gate from `lapi.Client.Close`. Nil-check (published Close panics on nil).
- Do not put backoff knobs on the reclaim key. First-wins at create, like `updateMaxFailure`.

## Pattern snippet

```go
ok, wait, err := c.gate.Allow(ctx, stem)
if err != nil || !ok {
	c.log.Debug("queryLiveDecisions:skipped", "wait", wait)
	return "", 0, errQuerySkipped
}
body, err := c.crowdsecQuery(routeURL.String(), nil)
_ = c.gate.Report(stem, err == nil && parsed)
```

## Key files

- `pkg/lapi/client.go`
- `pkg/lapi/client_live.go`
- `pkg/lapi/client_decisions.go`
- `pkg/configuration/configuration.go`

## Gotchas

- Cache hits in `Bouncer.ServeHTTP` skip `LiveLookup` (no Allow).
- Metrics POST and stream polls stay ungated.
- Client address stays `pkg/ip.GetRemoteIP` via `clientRequest.remoteIP`. Do not parse `RemoteAddr`.
- `Jitter` `0` disables jitter only. CreateConfig defaults avoid the partial-Config omit footgun.
