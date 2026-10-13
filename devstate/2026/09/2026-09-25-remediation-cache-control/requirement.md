# Requirement
IssueKey: 2026-09-25-remediation-cache-control

## Problem
A CDN in front of Traefik stored the captcha HTML this plugin writes (HTTP 200 on the original URL, Content-Type only, no Set-Cookie). After the captcha decision was cleared, the CDN kept serving that stored page.

## Current (code)
- Captcha challenge HTML is written by `pkg/captcha/captcha.go` `Client.ServeHTTP`. On a non-`Pass` outcome it sets `Content-Type` from the template, the optional remediation header, then `WriteHeader(200)` and executes the challenge template. It does not set `Cache-Control`. It does not set `Set-Cookie` on this path (the gate cookie is only issued on `Pass` before the 302).
- Ban HTML is written by `pkg/bouncer/bouncer.go` `handleBanServeHTTP`. It sets the optional remediation header, `Content-Type` from `banTemplateContentType`, then `WriteHeader` with `remediationStatusCode`, and executes `banTemplate` when present and the method is not HEAD. It does not set `Cache-Control`.
- AppSec challenge relay already copies `user_headers` onto the writer (hop-by-hop and `Set-Cookie` skipped): `pkg/bouncer/bouncer.go` `handleAppsecResponseServeHTTP`. If the engine sends `Cache-Control`, it is already relayed.
- Captcha ServeHTTP tests assert 200 + body and the solve 302 + gate cookie; they do not assert `Cache-Control`: `pkg/captcha/zzz_servehttp_test.go`.
- Ban ServeHTTP tests assert status, remediation header, body, and `Content-Type`; they do not assert `Cache-Control`: `pkg/bouncer/zzz_bouncer_test.go` (`TestHandleBanServeHTTP` / `TestHandleBanServeHTTPContentType`).

## Desired
- Set `Cache-Control: no-cache, no-store` on the captcha challenge response written by `Client.ServeHTTP`.
- Set the same `Cache-Control` header on the ban page written by `handleBanServeHTTP`.
- Match the header CrowdSec already uses on the HAProxy bouncer captcha/ban returns and on the AppSec challenge protocol example (`no-cache, no-store`).

## Affected
- `pkg/captcha/captcha.go` `Client.ServeHTTP` (challenge HTML path).
- `pkg/bouncer/bouncer.go` `handleBanServeHTTP`.
- Tests that assert headers on those two writers (`pkg/captcha/zzz_servehttp_test.go`, `pkg/bouncer/zzz_bouncer_test.go`).

## Out of scope
- AppSec challenge relay (`handleAppsecResponseServeHTTP`); it already copies `user_headers`, including `Cache-Control` from the engine.
- Adding `Set-Cookie` on the captcha challenge page.
- Changing the captcha HTTP 200 or ban status code.
- CDN configuration.
- The `Pass` 302 / `WriteSolvedRedirect` path in `Client.ServeHTTP` (ticket names the challenge HTML response).

## Unknowns
- Whether the live HAProxy bouncer and AppSec protocol example use exactly `no-cache, no-store` or additional directives. Ticket states that value; vendor confirmation is explore/research.
- Whether existing header tests must gain `Cache-Control` assertions, or a new neighbor test is the right place.
- CDN cache-key / TTL behavior in the reported deployment (not in this tree).

## Tensions
- `Client.ServeHTTP` also writes a 302 + gate cookie on `Pass`. The ticket describes the 200 challenge page (Content-Type only, no Set-Cookie) and names that challenge response, not the redirect.
- AppSec relay already copies engine `Cache-Control`; the ticket says leave that path unchanged.
