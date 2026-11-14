## Context

See proposal.md for why. `applyAppsecServeHTTP` routes `appsec.ActionBan` to `handleBanServeHTTP`, which always writes `remediationStatusCode`. `handleBanServeHTTP` has 10 production callers in `pkg/bouncer/bouncer.go`; only the AppSec ban site has an AppSec status. The listener answers a `RateLimit()` block with its blocked code (403), so `pkg/appsec/query.go` already returns `Response{Action: ban, HTTPStatus: 429}` (`knowledge/research/ext_crowdsec_appsec_rate-limit/`).

## Goals / Non-Goals

**Goals:**
- AppSec ban with `http_status` 429 → client 429 on the operator ban page.
- Every other ban path and every other AppSec ban status keeps `remediationStatusCode`.
- Unit tests and a real-stack e2e that fail on master.

**Non-Goals:**
- `Retry-After`, a generic rate-limiter leg, honouring other AppSec ban codes.
- `pkg/appsec/query.go` listener status mapping.
- A distinct remediation header reason for rate limits.

## Decisions

- `handleBanServeHTTP` keeps its signature and delegates to a ban writer that takes the status. The AppSec ban case passes the status from a `Bouncer` helper that returns 429 when `decision.HTTPStatus` is 429, else `remediationStatusCode`. Alternative: a status argument on all 10 callers — rejected; 9 never vary it.
- Only 429 is honoured. Alternative: any `http_status` — rejected; `SetReturnCode()` would override the operator's `bouncerRemediationStatusCode`.
- Header stays `ban:appsec`. Alternative: `ban:appsec-rate-limit` — rejected; the bouncer cannot tell `RateLimit()` from `SetReturnCode(429)`.
- e2e runs on the 7422 CRS listener (`acquis.yaml` now lists `crowdsecurity/crs-inband` and local `e2e/rate-limit`) through a new AppSec-only router `/ratelimit` with the e2e ban page and remediation header. The 7423 bot-detection listener is avoided so its challenge hooks cannot answer first. Alternative: 7423 — rejected for that reason. CrowdSec image moves to `v1.8.2`, the first release with `RateLimit()`.

## Risks / Trade-offs

- [CrowdSec image bump] → other real-stack cases could change on v1.8.2; the e2e jobs run the whole suite on the bumped image.
- [RateLimit bucket per client IP, in memory] → the e2e case uses its own `X-Forwarded-For`; a CrowdSec restart resets the bucket.
- [Operator set `bouncerRemediationStatusCode` deliberately] → a 429 from AppSec still wins; documented in README.

## Migration Plan

- No config or stored-data change. Rollback restores `remediationStatusCode` for every AppSec ban.
