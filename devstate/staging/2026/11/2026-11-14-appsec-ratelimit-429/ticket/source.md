# Return 429 to the client when AppSec bans with http_status 429

CrowdSec 1.8 AppSec can rate-limit inside a hook (`RateLimit("login","2/m")`). When the limit is exceeded, the AppSec listener answers the bouncer with its blocked code (403 by default, `BouncerBlockedHTTPCode`) and the body `{"action":"ban","http_status":429}`. Source: crowdsecurity/crowdsec `pkg/appsec/ratelimit.go` sets `UserHTTPResponseCode = http.StatusTooManyRequests` and `BouncerHTTPResponseCode = w.Config.BouncerBlockedHTTPCode`. Clients that back off on 429 (the upstream issue cites a Vaultwarden mobile app) do not back off on 403.

On master (this fork), `case appsec.ActionBan` in `pkg/bouncer/bouncer.go` (`applyAppsecServeHTTP`) calls `handleBanServeHTTP`, which always writes `b.remediationStatusCode` (`bouncerRemediationStatusCode`, default 403). The `http_status` of an AppSec ban is ignored. No code references 429.

Desired:
- An AppSec ban whose `http_status` is 429 is answered with 429. Same operator ban template, same `Content-Type`, same `Cache-Control`, same remediation header (`ban:appsec`), same dropped metrics (origin `appsec`, remediation `ban`), HEAD still has no body.
- Any other AppSec ban `http_status` (403, 418, 0, missing) keeps `bouncerRemediationStatusCode`. Do not honour arbitrary `SetReturnCode()` values.
- 429 wins over a configured `bouncerRemediationStatusCode` (for example 503).
- The `pkg/appsec/query.go` listener-status handling (only 200 and 403 accepted) stays as is: the listener answers 403 for a RateLimit block.

Decisions already taken with the requester (2026-11-14):
- Limit the 429 to AppSec. Do not generalise it for the future rate-limiter leg.
- No `Retry-After` header: AppSec does not provide that value.
- Keep the remediation header value `ban:appsec`. The bouncer cannot tell `RateLimit()` from `SetReturnCode(429)`, and the 429 is already visible in access logs.

Tests:
- Unit (pkg/bouncer): ban/429 → 429 with the operator template; ban/403 and ban/418 → `remediationStatusCode`; ban without `http_status` → `remediationStatusCode`; ban/429 with `remediationStatusCode` 503 → 429; HEAD + ban/429 → 429 without body.
- Real e2e (tests/e2e/real, Pester + docker compose): an AppSec config that uses `RateLimit()` on a dedicated path, and a test that exceeds the limit and sees 429 with the ban page. If the CrowdSec image in the e2e stack (`crowdsecurity/crowdsec:v1.8.0`) does not support `RateLimit()`, bump the image to a version that does.

Docs: README `BouncerRemediationStatusCode` entry and the remediation table say that an AppSec ban with `http_status` 429 is answered with 429.

Out of scope: a generic rate-limiter leg, `Retry-After`, honouring other AppSec ban status codes, the AppSec captcha/challenge relay, `pkg/appsec/query.go` listener status mapping.

Upstream (must appear on the delivery card):
- Issue https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/421
- PR https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/422 (commit 0004a05c). Do not copy that patch; it edits the old root `bouncer.go`, which master does not have.
- Fork review: `upstream-review-2026-11-14.md` problem 4 (P2).
