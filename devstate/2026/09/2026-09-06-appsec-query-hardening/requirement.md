# Requirement
IssueKey: 2026-09-06-appsec-query-hardening

## Problem
The AppSec `Query` forward path in `pkg/appsec` has four bugs on one HTTP round-trip: 502/503/504 responses leak connections because the body is never drained; outbound POST headers can disagree with the truncated body sent to AppSec; response body read failures always ban regardless of `crowdsecAppsecFailureAction`; and `crowdsecAppsecBodyLimit: 0` silently drops POST bodies while metadata still says POST.

## Current (code)
- `pkg/appsec/query.go:98-103` — on `Do` error or `isReverseProxyError(res.StatusCode)`, `Query` returns via `resultForFailureAction` before `defer c.drainResponse(res)` at line 103; undrained body when `res` is non-nil.
- `pkg/appsec/client.go:99-103` — `isReverseProxyError` matches 502, 503, 504.
- `pkg/appsec/query.go:169-177` — `drainResponse` reads leftover bytes for connection reuse.
- `pkg/appsec/query.go:128-131` — after `newAppsecBodyRequest`, every client header is copied with `Add`, including stale `Content-Length`, `Transfer-Encoding`, and hop-by-hop names.
- `pkg/appsec/query.go:152-162` — POST body is capped via `io.LimitReader(httpReq.Body, c.appsecBodyLimit)`; remainder stays on `httpReq.Body` for downstream.
- `pkg/bouncer/bouncer.go:337-341` — AppSec response to client strips hop-by-hop headers; forward path has no equivalent.
- `pkg/appsec/query.go:110-113` — `readCappedAppsecBody` error returns `(nil, err)` without `resultForFailureAction`.
- `pkg/bouncer/bouncer.go:306-314` — any AppSec error except `ErrFailureCaptcha` triggers ban via `handleBanServeHTTP`.
- `pkg/appsec/query.go:152-165` — body copy requires `c.appsecBodyLimit > 0`; otherwise `default` branch issues GET with nil body.
- `pkg/appsec/query.go:135-137` — `X-Crowdsec-Appsec-Verb` still reflects original method when body is dropped.
- `pkg/configuration/configuration.go:522-523` — validates `CrowdsecAppsecBodyLimit < 0` only; `0` passes.
- `pkg/appsec/query_test.go:148-177` — connection reuse tested for 200/403/500, not 502/503/504.
- `pkg/appsec/query_test.go` — no outbound header/body-length assertion after POST truncation.
- `pkg/appsec/failure_action_test.go` — covers unreachable and 500 only, not read errors.
- `pkg/appsec/query_test.go` — no test for `appsecBodyLimit == 0` with POST body.

## Desired
- Drain AppSec response bodies on all paths where `Do` returns a non-nil `res`, including 502/503/504 before failure-action return.
- After building the outbound POST body, strip or replace body-size and hop-by-hop headers so they match bytes actually sent; optionally signal truncation via metadata header.
- Route response read/parse transport failures through `resultForFailureAction` like unreachable and 500 paths.
- Define and implement explicit contract for `crowdsecAppsecBodyLimit: 0` (unlimited, reject at validate, or failure-action on drop — pick one documented behavior; do not silently drop).
- Add tests for all four paths.

## Affected
- `pkg/appsec/query.go` (primary)
- `pkg/appsec/query_test.go`
- `pkg/appsec/failure_action_test.go`
- Possibly `pkg/configuration/configuration.go` if `0` is rejected at validate time

## Out of scope
- Streaming/unreadable body path (`isBodyUnreadable`) — already applies failure action for non-passthrough.
- `pkg/appsec/session.go` / reclaim — no local defect cited.
- Network `Do` errors where `res` is nil (no body to drain).
- Intentional GET forwarding for unreadable HTTP/2 streams.
- URI/host forwarding via `X-Crowdsec-Appsec-*` headers.
- Non-200 empty-body errors from `interpretAppsecBody` (AppSec verdict, not infrastructure failure).
- Default 10 MiB truncation when limit > 0 except header metadata fix.

## Unknowns
- Whether `crowdsecAppsecBodyLimit: 0` should mean unlimited or be rejected at validation — ticket asks to pick a documented contract; no existing operator docs found in scope.

## Tensions
- Body-limit `0`: sibling finding suggests unlimited, reject, or failure-action; main ticket says "pick the documented contract" — no current documented contract in tree.
- Read errors vs `interpretAppsecBody` non-200 errors: ticket wants failure-action on transport read failures but explicitly excludes definitive AppSec HTTP status without envelope.
- Header rebuild may need configuration touch if `0` is rejected at validate — scope bound to `pkg/appsec` but validation lives in `pkg/configuration/configuration.go`.
