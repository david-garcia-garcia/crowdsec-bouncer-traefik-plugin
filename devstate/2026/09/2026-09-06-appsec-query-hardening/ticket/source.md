# AppSec reverse-proxy drain, stale body headers, read-error failure-action, and body-limit 0

## Problem
`pkg/appsec` query path has four production bugs on one request-forward flow:

1. 502/503/504 return before `defer drainResponse` → connection leak.
2. Client headers copied after body rebuild/truncation → wrong Content-Length / hop-by-hop leftovers.
3. Response read errors bypass `failureAction` → always ban.
4. `crowdsecAppsecBodyLimit: 0` silently drops POST bodies.

## Evidence
Sibling files: `reverse-proxy-error-skips-response-drain.md`, `forward-request-headers-stale-body-metadata.md`, `response-read-error-ignores-failure-action.md`, `body-limit-zero-silently-drops-body.md`.

## Current behavior
Error statuses skip drain. Forwarded request metadata can disagree with the body actually sent. Read failures ignore configured failure-action. Limit 0 is treated as "send nothing" without a clear contract.

## Desired
Drain the AppSec response on all status paths that leave a body. Rebuild hop-by-hop and Content-Length from the body actually forwarded. Apply `failureAction` on response read errors. Define and test body-limit 0 (unlimited vs drop — pick the documented contract; do not silently drop). Tests for those four paths.

## Out of scope
Streaming/unreadable body already covered. Reclaim session.go (no local defect).

---

## Sibling: reverse-proxy-error-skips-response-drain

### Problem
When AppSec (or a proxy in front of it) returns 502, 503, or 504, `Query` applies the configured failure action but returns before registering `defer c.drainResponse(res)`. The response body stays unread and the idle connection cannot be reused.

### Evidence
- pkg/appsec/query.go:98-103 — `Do` error or `isReverseProxyError` returns immediately; `defer c.drainResponse(res)` is on the next line.
- pkg/appsec/client.go:99-103 — `isReverseProxyError` matches 502, 503, 504.
- pkg/appsec/query.go:169-177 — `drainResponse` exists specifically to allow connection reuse.
- pkg/appsec/query_test.go:148-177 — connection-reuse test covers 200, 403, and 500 only; 502/503/504 are not exercised.

### Desired
Register `defer c.drainResponse(res)` immediately after a non-nil `res` from `Do`, or call `drainResponse` before every early return that follows a successful HTTP round-trip. Add a connection-reuse test that loops on 502 (and optionally 503/504).

---

## Sibling: forward-request-headers-stale-body-metadata

### Problem
`newAppsecForwardRequest` builds a new POST with a copied (and possibly truncated) body, then blindly copies every header from the original client request. Stale `Content-Length`, `Transfer-Encoding`, and hop-by-hop headers can disagree with the actual bytes sent to AppSec.

### Evidence
- pkg/appsec/query.go:124-131 — `newAppsecBodyRequest` creates the outbound request first.
- pkg/appsec/query.go:128-131 — all `httpReq.Header` entries are copied with `Add` onto the new request.
- pkg/appsec/query.go:152-162 — body is read through `io.LimitReader(httpReq.Body, c.appsecBodyLimit)`.
- pkg/appsec/query_test.go — no test asserts outbound AppSec request headers or body length after POST forwarding or truncation.
- pkg/bouncer/bouncer.go:337-341 — response path strips hop-by-hop headers when writing AppSec envelopes to the client.

### Desired
After building the outbound body, strip or replace body-size and hop-by-hop headers so they match the POST actually sent. Tests should POST a body larger than the limit and assert the AppSec stub sees consistent length headers and byte count.

---

## Sibling: response-read-error-ignores-failure-action

### Problem
After AppSec returns a non-error HTTP status, a failure while reading the response body bypasses `resultForFailureAction` and returns a raw error. The bouncer treats any non-`ErrFailureCaptcha` error as a ban, ignoring `crowdsecAppsecFailureAction: passthrough` or `captcha`.

### Evidence
- pkg/appsec/query.go:110-113 — `readCappedAppsecBody` error returns `(nil, err)` with no `pol.FailureAction` handling.
- pkg/appsec/query.go:99-107 — unreachable and HTTP 500 paths call `resultForFailureAction(pol.FailureAction, ...)`.
- pkg/bouncer/bouncer.go:306-314 — `applyAppsecServeHTTP` bans on any error except `ErrFailureCaptcha`.
- pkg/appsec/failure_action_test.go — covers 500 and unreachable only; no read-error scenario.

### Desired
Route read/parse transport failures through `resultForFailureAction` the same way unreachable and 500 responses do. Add a test that simulates a body read failure with `FailureActionPassthrough` and asserts allow/passthrough instead of ban.

---

## Sibling: body-limit-zero-silently-drops-body

### Problem
When `crowdsecAppsecBodyLimit` is `0`, `newAppsecBodyRequest` never enters the body-copy branch and always builds a GET with no body, while `X-Crowdsec-Appsec-Verb` still reflects the original method (e.g. POST). Validation accepts `0` (`>= 0`).

### Evidence
- pkg/appsec/query.go:152-166 — body forwarding requires `c.appsecBodyLimit > 0 && httpReq.Body != nil`.
- pkg/appsec/query.go:135-137 — verb/host/URI metadata still reflect the original client request.
- pkg/configuration/configuration.go:166 — default body limit is 10485760; zero is not the default but is valid.
- pkg/configuration/configuration.go:522-523 — validates `CrowdsecAppsecBodyLimit < 0` only.

### Desired
Treat `0` as unlimited, or reject `0` at validate time, or apply `FailureAction` when a method-with-body would be dropped. Add a test for POST + limit 0 documenting expected behavior.
