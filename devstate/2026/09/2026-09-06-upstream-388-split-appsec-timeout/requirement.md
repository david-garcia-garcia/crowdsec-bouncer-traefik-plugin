# Requirement
IssueKey: 2026-09-06-upstream-388-split-appsec-timeout

## Problem

A single `HTTPTimeoutSeconds` (default 10) governs both slow LAPI stream pulls and fast per-request AppSec calls. When AppSec is unreachable, every request waits the full LAPI-oriented timeout before fail-open proceeds, making the site unusable if the value is tuned long for stream pulls.

## Current (code)

- `pkg/configuration/configuration.go:96` — `HTTPTimeoutSeconds int64`, default `10` at `:185`.
- `pkg/configuration/configuration.go:505-510` — validates `HTTPTimeoutSeconds >= 1` (seconds only).
- `pkg/lapi/client.go:169` — LAPI `http.Client.Timeout` = `HTTPTimeoutSeconds * time.Second`.
- `pkg/appsec/client.go:72` — AppSec `http.Client.Timeout` = same `HTTPTimeoutSeconds * time.Second`.
- `pkg/bouncer/bouncer.go:91` — captcha siteverify client uses same `HTTPTimeoutSeconds * time.Second`.
- `pkg/appsec/session.go:24,37` — AppSec reclaim identity hashes shared `HTTPTimeoutSeconds`.
- `pkg/lapi/identity.go:34,63` / `pkg/lapi/session.go:79,115` — LAPI reclaim identity also includes `HTTPTimeoutSeconds`.
- `README.md:481` — documents single `HTTPTimeoutSeconds` for LAPI contact.
- Tests: no unit or e2e asserting AppSec can use a tighter timeout than LAPI with fail-open (`388-assessment.md` evidence).

## Desired

- Add a separate AppSec timeout setting (e.g. `AppsecTimeoutSeconds`) defaulting to `HTTPTimeoutSeconds` when unset.
- Wire AppSec `http.Client.Timeout` (and AppSec reclaim identity) to the AppSec-specific value.
- Support finer-than-second granularity for AppSec (milliseconds), as requested upstream.
- Keep LAPI stream/live pulls on `HTTPTimeoutSeconds` (long timeout use case unchanged).
- Add tests that AppSec uses a tighter timeout than LAPI and fail-open still works when AppSec is slow/unreachable.

## Affected

- `pkg/configuration/configuration.go`
- `pkg/appsec/client.go`
- `pkg/appsec/session.go`
- `README.md` (AppSec timeout config surface)
- New/extended tests under `pkg/appsec/` (and possibly configuration validation tests)

## Out of scope

- Splitting captcha siteverify onto its own timeout (still uses `HTTPTimeoutSeconds` today; ticket silent).
- Changing LAPI timeout semantics or adding LAPI millisecond config.
- Upstream PR to maxlerebourg repo (fix on this fork only).
- Broader HTTP client transport tuning (idle conn limits, TLS).
- E2E against real CrowdSec AppSec appliance (unless existing e2e harness already covers AppSec fail-open).

## Unknowns

- Exact JSON field name and whether milliseconds are a separate field or sub-second values on one duration field.
- Whether reclaim identity should hash the resolved effective AppSec timeout or the raw config fields.
- Whether README / devdocs need a dedicated AppSec timeout section vs extending existing HTTP timeout docs.

## Tensions

- Millisecond AppSec timeout vs existing int64 seconds validation pattern in `configuration.go`.
- AppSec reclaim identity currently keys on `HTTPTimeoutSeconds`; switching to AppSec-specific timeout changes reclaim/session keys for existing deployments tuning only LAPI timeout.
- Ticket asks fail-open when AppSec unreachable; captcha path sharing `HTTPTimeoutSeconds` may still block requests on slow captcha verify (not in ticket scope).
