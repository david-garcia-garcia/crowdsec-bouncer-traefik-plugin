# Explore

## Concepts

Live/none LAPI and AppSec always attempt HTTP toward their backend. Dest has no admission gate. Stream/alone already skip per-request LAPI via `UpdateMaxFailure` / `StreamHealthy` and stay out of scope.

```
  request
     │
     ▼
  cache hit? ──yes──► remediate / pass (no HTTP, no Allow)
     │ no
     ▼
  LiveLookup / AppSec Query
     │
     ▼
  Allow(ctx, backendURL)
     ├─ ok=false, err=nil ──► today's FailureAction (no GET/Do)
     ├─ err != nil         ──► same FailureAction path (no GET/Do)
     └─ ok=true
           │
           ▼
        GET / Do
           │
           ▼
        Report(backendURL, success)
           │
           ▼
        existing parse / merge / FailureAction
```

`backendbackoff` is already in utilities `v1.0.3` (`950b08de86b6fd9ea68ac1d205e17a379ec60522`). Dest requires that tag; `vendor/modules.txt` lists only `reclaim` and `simpleredis` because dest does not import the package yet. Import + `go mod vendor` is enough. Do not bump. Do not copy into `pkg/`. Do not add `pkg/health`. Do not import traefik-modsecurity.

One `*backendbackoff.Gate` lives on the reclaimed live/none `lapi.Client` and one on the reclaimed `appsec.Client`. Construct in that Client's `New` (create-once). `Close` the gate from the existing Client `Close` hook. Sleep/Wake do not touch the gate (published API has neither). Traefik `New` ctx is the reclaim holder (`std_go_reclaim`, `pkg/reclaim`, `core_plugin_middleware`). Do not add `sync.Once` or a package-global gate.

Allow/Report key is the backend URL stem the Client already composes (`scheme` + `host` + `path` on `queryLiveDecisions` / `newAppsecForwardRequest`). Not the client address. Not the reclaim key (Redis, key material, body limit, metrics interval).

Published `New(Config)`: fully zero Config applies defaults (FailureRatio 0.30, TripFailures 5, BaseCooldown 1s, MaxCooldown 10s, Jitter 0.10, TTL 60s). Partial Config fills zeros except Jitter 0, which disables jitter only. There is no published skip-off. The library does not sleep and does not write HTTP.

## Decisions

- Import `github.com/david-garcia-garcia/traefik-middleware-utilities/backendbackoff` from `pkg/lapi` and `pkg/appsec`. Vendor it. Stay on `v1.0.3`.
- One shared plugin knob set (same pattern as `HTTPTimeoutSeconds`), applied independently when each Client constructs its Gate. CreateConfig defaults match package defaults so we always pass a full Config and avoid the partial-Config Jitter-0 footgun.
- Construct a Gate only on live/none LAPI Clients and on AppSec Clients. Stream/alone `lapi.New` keeps a nil gate. Nil Close/Allow is a no-op skip (stream stays on `UpdateMaxFailure`).
- One Allow per `queryLiveDecisions` GET and one Allow per AppSec `Do`. Denied GET returns a query error so existing fail-closed / active-ban-outranks / FailureAction stay. After the gate trips, later scope GETs in the same lookup also skip HTTP.
- Thread the inbound request context into `LiveLookup` (`req.Request.Context()`). AppSec already has `httpReq.Context()`. Do not use constructor ctx or `context.Background()`. Do not sleep on Allow's wait; Debug-log it.
- LAPI Report success when HTTP+parse produced a remediation value (ban, captcha, or none). Report failure on query/HTTP/parse/duration-parse errors. A backend that answered is healthy.
- AppSec Report failure only on Do error, 502/503/504, and HTTP 500. Inbound unreadable body never Does (today's FailureAction, no Report). After an admitted Do, response-body io (`errAppsecReadBody`), parse, 200/403 envelopes, and oversized-body handling Report success (backend answered). FailureAction on those paths is unchanged.
- Always construct the gate when the Client is supposed to have one. No product enabled flag. Jitter 0 only disables jitter. Document package defaults in README.
- Gate knobs stay off the reclaim key (first-wins at create, like `updateMaxFailure`). Last `New` still `AdoptTransport`s TLS/timeout.
- Denied or Allow-error: today's FailureAction without GET/Do. Distinct skip error string (do not reuse `unreachable` / `banned`). No new action enums.
- Cache hits in `Bouncer.ServeHTTP` still skip `LiveLookup` entirely (no Allow). Metrics POST and stream polls stay ungated.
- Propose a new spec leaf; do not fold the gate into `core_plugin_lapi_connection` (that leaf is replaceable transport).

## Open questions

- Q: One Allow per `LiveLookup` vs one Allow per `queryLiveDecisions` GET (IP plus each header scope)?
  Decision: assumed — one Allow per GET (`queryLiveDecisions`). Desired text is "Before LAPI GET / AppSec Do". One Allow per lookup would still hammer a dead LAPI for remaining scopes after the first GET failed.
  By: explore

- Q: Whether LAPI captcha/allow (backend answered, not ban) Reports success the same as ban?
  Decision: assumed — yes. Report success on any HTTP+parse that yielded a remediation value (ban, captcha, or none). Health is "backend answered," not the remediation kind.
  By: explore

- Q: Whether AppSec response-body io errors (`errAppsecReadBody`) are the ticket’s "unreadable body" or only the inbound `isBodyUnreadable` path?
  Decision: assumed — inbound `isBodyUnreadable` only (no Do, no Report). After an admitted Do, `errAppsecReadBody` Reports success because Desired lists Do error / 502/503/504 / HTTP 500 as the failure set; dest still applies FailureAction on the read error.
  By: explore

- Q: How to disable skip, given published `New` has no off switch (zero Config enables defaults)?
  Decision: assumed — always construct the live/none and AppSec gates. Product nil-gate only for stream/alone LAPI (out of scope). Do not invent an enabled flag or a second Tracker. Jitter 0 disables jitter only.
  By: explore

- Q: Exact plugin field names and whether LAPI/AppSec share one knob set?
  Decision: assumed — one shared set on `configuration.Config`, CreateConfig defaults = package defaults: `backendBackoffFailureRatio` (0.30), `backendBackoffTripFailures` (5), `backendBackoffBaseCooldownSeconds` (1), `backendBackoffMaxCooldownSeconds` (10), `backendBackoffJitter` (0.10), `backendBackoffTTLSeconds` (60). Validate like other numeric knobs; reject values `backendbackoff.New` would reject. Document in README.
  By: explore

- Q: Who already owns the client address this path must not reconstruct?
  Decision: resolved — `pkg/ip.GetRemoteIP` via `clientRequest.remoteIP` (`core_plugin_ip`). Gate key is not the client address. AppSec still reuses that `ip` on `X-Crowdsec-Appsec-Ip`. Do not parse `RemoteAddr` on LAPI or AppSec.
  By: explore

- Q: Who already owns the backend identity used as Allow/Report key (ticket: LAPI URL / AppSec URL, not reclaim key material)?
  Decision: assumed — the Client-stored URL stem already composed for the HTTP attempt (`crowdsecScheme`/`Host`/`Path` on LAPI; `appsecScheme`/`Host`/`Path` on AppSec). Reuse that string. Do not use `lapi.Key` / `appsec.Key` (Redis, key, body limit, metrics interval). Do not hash a second identity.
  By: explore

- Q: Who already owns request cancellation and Host if this work would set or reconstruct them?
  Decision: resolved — inbound `*http.Request`: `Context()` for Allow, `Host` for the existing AppSec header copy. Reuse those. Do not build a timeout context from `HTTPTimeoutSeconds` (already on the HTTP client).
  By: explore
