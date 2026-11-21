# Ban page

## Language

**Ban page**:
The operator remediation HTTP response `handleBanStatusServeHTTP` writes: a status (`remediationStatusCode` through `handleBanServeHTTP`; the AppSec `http_status` from 200 to 599 for an AppSec ban), `Content-Type` from the ban template, optional template body. Not AppSec envelope relay and not captcha `ServeHTTP`.
_Avoid_: AppSec `user_body_content`, captcha challenge HTML

## Overview

Ban kind (and captcha fallbacks that ban) share one writer. Pass `headerReason` at each call site. Set response headers before `WriteHeader`. HEAD, a nil template, and a 204 or 304 status skip the body and still carry those headers.

## How to use

- Set `Cache-Control: no-cache, no-store` next to `Content-Type` and before `WriteHeader`.
- HEAD and nil-template bans inherit that Set the same way `Content-Type` already does.
- Do not add extra directives (`private`, `max-age`, `must-revalidate`, `Pragma`).
- Set `Retry-After` next to `Cache-Control`, before `WriteHeader`, only when the status written is 429 and `decisionLeft > 0`. The value is `retryAfterSeconds(decisionLeft)`: whole seconds rounded up, at least `1` (RFC 9110 delay-seconds). HEAD and nil-template bans carry it like `Cache-Control`.
- `decisionLeft` is the time left on the LAPI decision the lookup chose. Only `serveLAPI` sets it (from `LookupRemediation` or `LiveLookup`) and passes it through `remediateUnderActionRules` → `handleRemediationServeHTTP` → `handleCaptchaKindServeHTTP` (downgrade ban) or `handleBanServeHTTP` → `handleBanStatusServeHTTP`. Every other caller passes the named zero `noLAPIDecisionEnd`: action-rule `ban`, captcha rule, LAPI / AppSec / ModSecurity failure actions, `banWarnCaptchaRule` (cache failure and every failure ban), and the AppSec ban with its `http_status`. So an AppSec `http_status` 429 never gets the header.
- Ban paths call `handleBanServeHTTP` (status `remediationStatusCode`). Only the AppSec ban calls `handleBanStatusServeHTTP` with `appsecBanStatusCode`, which relays the AppSec `http_status` when it is from 200 to 599 (CrowdSec always sends one: 403 by default, 429 for `RateLimit()`, or the `SetReturnCode()` / `user_blocked_http_code` value) and falls back to `remediationStatusCode` otherwise. Do not swap the 403 for `remediationStatusCode`: the bouncer cannot tell the default from `SetReturnCode(403)`.
- Do not emit Cache-Control from AppSec relay; copy `user_headers` as they arrive (`core_plugin_appsec`).
- Pass an explicit `headerReason` into `handleBanServeHTTP` next to template `reason` and metrics `origin`. When `remediationCustomHeader` is set, write `formatRemediationHeader("ban", headerReason, origin)`. Closed reasons never take a third field; `lapi` plus a non-empty origin appends the encoded origin. Do not infer captcha-downgrade / `appsec` / `appsec-challenge-empty` / `appsec-action-empty` from origin alone.
- Do not share a helper package with captcha `ServeHTTP`. Captcha does not import the closed table; the bouncer formats the challenge-page value.

## Pattern snippet

```go
if b.remediationCustomHeader != "" {
	if value := formatRemediationHeader(headerKindBan, headerReason, origin); value != "" {
		rw.Header().Set(b.remediationCustomHeader, value)
	}
}
rw.Header().Set("Content-Type", b.banTemplateContentType)
rw.Header().Set("Cache-Control", "no-cache, no-store")
if statusCode == http.StatusTooManyRequests && decisionLeft > 0 {
	rw.Header().Set("Retry-After", retryAfterSeconds(decisionLeft))
}
rw.WriteHeader(statusCode)
```

## Key files

- `pkg/bouncer/bouncer_serve_remediation.go` (`handleBanServeHTTP`, `handleBanStatusServeHTTP`)
- `pkg/bouncer/bouncer_serve_appsec_verdict.go` (`appsecBanStatusCode`)
- `pkg/bouncer/remediation_header.go`

## Gotchas

- All ban call sites inherit the one Set on `handleBanStatusServeHTTP` (`handleBanServeHTTP` forwards `remediationStatusCode` to it). Each site passes its own `headerReason`.
- Challenge HTML Cache-Control lives on `core_plugin_middleware_captcha-widget`, not here.
- Do not set `Retry-After` on `rw` in `serveLAPI` before dispatch: it would leak onto a captcha challenge, a cleared gate or bypassCaptcha pass-through, and a later AppSec or ModSecurity answer.
- A stream/alone Range winner has no end (the Range blob has none), so its ban has no `Retry-After`. In live/none, LAPI expands Range on `?ip=` and returns the duration, so that ban gets it.
