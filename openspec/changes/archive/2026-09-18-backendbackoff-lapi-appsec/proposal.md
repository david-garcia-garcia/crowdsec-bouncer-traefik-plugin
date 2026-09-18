## Why

Live LAPI and AppSec call a dead backend on every request. Dest has no admission gate. Closed PR #55 copied an in-tree Tracker; the owner declined that copy. Utilities `v1.0.3` already publishes `backendbackoff` — dest requires that tag and only needs an import plus vendor.

## What Changes

- Import `github.com/david-garcia-garcia/traefik-middleware-utilities/backendbackoff` from `pkg/lapi` and `pkg/appsec`. Vendor it. Stay on `v1.0.3`. Do not copy the package into `pkg/`. Do not add `pkg/health`. Do not import traefik-modsecurity.
- Construct one `*backendbackoff.Gate` on the reclaimed live/none `lapi.Client` and one on the reclaimed `appsec.Client`. Stream/alone LAPI keeps a nil gate (still `UpdateMaxFailure` / `StreamHealthy`).
- Before each live LAPI GET and each AppSec `Do`: `Allow` with the backend URL stem. Denied or Allow-error takes today's FailureAction path with no GET/Do. Distinct skip error (do not reuse `unreachable` / `banned`). No new action enums.
- After an admitted attempt: `Report`. LAPI success is HTTP+parse that yielded a remediation value (ban, captcha, or none). AppSec failure is Do error, 502/503/504, or HTTP 500 only.
- One shared plugin knob set (same pattern as `HTTPTimeoutSeconds`). CreateConfig defaults match package defaults. Document in README. No product enabled flag.
- `Gate.Close()` from existing Client `Close` hooks.
- Tests: after enough failures the next `LiveLookup` / `Query` does not hit the test server and still applies FailureAction; a success `Report` recovers; stream polls stay ungated.

## Capabilities

### New Capabilities

- `core_plugin_lapi_backend-backoff`: live/none LAPI admission via published `backendbackoff.Gate` (Allow per GET, Report after the attempt, Close on Client Close).
- `core_plugin_appsec_backend-backoff`: AppSec Query admission via published `backendbackoff.Gate` (Allow per Do, Report after an admitted Do, Close on Client Close).

### Modified Capabilities

- `core_plugin_middleware_config-validation`: shared `backendBackoff*` knobs on `CreateConfig` / `ValidateParams`; reject values `backendbackoff.New` would reject.

## Impact

- `pkg/lapi` live/none lookup (`queryLiveDecisions`), `LiveLookup` request context, Client `New` / `Close`
- `pkg/appsec` `Query` and Client `New` / `Close`
- `pkg/bouncer` passes `req.Request.Context()` into `LiveLookup`
- `pkg/configuration` public knobs + `CreateConfig` defaults + `ValidateParams`
- README defaults for the new knobs
- `go.mod` / `vendor/` after the import (no version bump)
- LiveLookup / AppSec Query tests
- Usage packets `knowledge/devdocs/core_plugin_lapi_backend-backoff.md` and `knowledge/devdocs/core_plugin_appsec_backend-backoff.md`
- No **BREAKING** public JSON/YAML keys (new keys only; omit keeps package defaults)
- Out of scope: captcha siteverify, Redis, Range, stream poll HTTP, `pkg/health`, copying `backendbackoff` into `pkg/`, traefik-modsecurity, closed PR #55
