# Requirement
IssueKey: 2026-09-18-backendbackoff-lapi-appsec

## Problem
Live LAPI and AppSec keep calling a dead backend on every request. Dest has no admission gate. Closed PR #55 copied an in-tree Tracker from traefik-modsecurity; owner declined that copy. Use published `backendbackoff` instead.

## Current (code)
- `go.mod` requires `traefik-middleware-utilities v1.0.3`. Path: `go.mod`.
- Dest vendor of that module lists only `reclaim` and `simpleredis`. Path: `vendor/modules.txt`.
- `backendbackoff` is not imported and is not under `pkg/`. Path: not found.
- Tag `v1.0.3` (`950b08de86b6fd9ea68ac1d205e17a379ec60522`) already contains `backendbackoff` on utilities master. Path: `knowledge/research/ext_traefik-middleware-utilities_backendbackoff/notes.md`.
- Live/none `LiveLookup` always GETs LAPI (`queryLiveDecisions` → `crowdsecQuery` / `httpClient.Do`) then the bouncer applies `CrowdsecLapiFailureAction` on a non-active remediation plus error. Paths: `pkg/lapi/client_live.go`, `pkg/lapi/client_decisions.go`, `pkg/lapi/client_http.go`, `pkg/bouncer/bouncer.go`.
- AppSec `Query` always `httpClient.Do` then `CrowdsecAppsecFailureAction` via `resultForFailureAction` on Do error, 502/503/504, and HTTP 500. Path: `pkg/appsec/query.go`.
- Unreadable inbound body is dropped in `newAppsecBodyRequest` before Do and uses FailureAction; it is not an HTTP attempt. Path: `pkg/appsec/query.go`.
- AppSec response `readCappedAppsecBody` io errors also use FailureAction. Path: `pkg/appsec/query.go`.
- Stream polls use `crowdsecQuery` / `UpdateMaxFailure` / `StreamHealthy`. Path: `pkg/lapi/client.go`, `pkg/lapi/client_stream.go`, `pkg/lapi/client_decisions.go`.
- One shared `HTTPTimeoutSeconds` is applied to LAPI and AppSec HTTP clients. Paths: `pkg/configuration/configuration.go`, `pkg/lapi/client_http.go`, `pkg/appsec/client_http.go`.
- Reclaimed `lapi.Client` (live/none via `OpenLive`) and `appsec.Client` already have reclaim `Close` hooks. Paths: `pkg/lapi/session.go`, `pkg/appsec/session.go`, `pkg/lapi/client.go`, `pkg/appsec/client.go`.
- No `pkg/health`. Path: not found.
- No import of `traefik-modsecurity`. Path: not found.

## Desired
- Import `github.com/david-garcia-garcia/traefik-middleware-utilities/backendbackoff`. Vendor it. Do not copy the package into `pkg/`. Do not add `pkg/health`. Do not import traefik-modsecurity.
- One `Gate` on the reclaimed live/none `lapi.Client` and one on the reclaimed `appsec.Client`. Allow/Report key is the backend identity (LAPI URL / AppSec URL), not the client IP.
- Before LAPI GET / AppSec Do: `Allow`. If denied (`ok=false`, `err=nil`), take today’s failure-action path without Do/GET. No new action enums.
- After an admitted attempt: `Report`. LAPI: query/HTTP/parse errors are failure; a ban (backend answered) is success. AppSec: Do error, 502/503/504, HTTP 500 are failure; unreadable body is not a backend failure.
- Map plugin `Config` onto `backendbackoff.Config` for LAPI and AppSec separately, or one shared set if explore keeps the existing shared `HTTPTimeoutSeconds` pattern. Document package defaults. Disable skip only as the published gate already allows (do not invent a second Tracker).
- `Gate.Close()` from existing client `Close` hooks.
- Tests: after enough failures, the next `LiveLookup` / `Query` does not hit the test HTTP server and still applies failure-action; a success `Report` recovers; stream polls stay on `UpdateMaxFailure` / `StreamHealthy` (no gate).

## Affected
- `pkg/lapi` live/none lookup and client Close
- `pkg/appsec` Query and client Close
- `pkg/configuration` public knobs + README defaults
- `go.mod` / `vendor/` after the import
- LiveLookup / AppSec Query tests

## Out of scope
- Captcha siteverify
- Redis
- Range
- Stream `UpdateMaxFailure` / `StreamHealthy` / stream poll HTTP
- In-tree `pkg/health` or traefik-modsecurity Tracker
- Copying `backendbackoff` into `pkg/`
- Closed PR #55 and branch `2026-09-06-crowdsec-client-failure-ratelimit`

## Unknowns
- One Allow per `LiveLookup` vs one Allow per `queryLiveDecisions` GET (IP plus each header scope).
- Whether LAPI captcha/allow (backend answered, not ban) Reports success the same as ban.
- Whether AppSec response-body io errors (`errAppsecReadBody`) are the ticket’s “unreadable body” or only the inbound `isBodyUnreadable` path.
- How to disable skip: published `New` has no off switch (zero Config enables defaults). Product nil-gate vs some other published behavior is for explore.
- Exact plugin field names and whether LAPI/AppSec share one knob set.

## Tensions
- Ticket says bump off `v1.0.3` because that tag lacks `backendbackoff`. Utilities `v1.0.3` already has the package; dest vendor omits it only because dest does not import it. No newer tag exists (master == `v1.0.3`).
- Ticket says disable skip the way the published gate supports. The published gate has no disable-skip field; `Jitter` 0 only disables jitter.
- Ticket key is LAPI URL / AppSec URL. Dest reclaim keys include key material, Redis, body limit, metrics interval — more than the URL.
- Closed #55 treated unreadable AppSec body as not a backend failure; dest today still applies FailureAction on inbound unreadable body and on response read errors. Report classification must not invent a new action enum.
