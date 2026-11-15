---
url: https://github.com/crowdsecurity/crowdsec/blob/e20782bb3c532f0b9b9a469c0bdaa003588ec8e5/pkg/appsec/appsec.go
title: pkg/appsec/appsec.go remediation constants and GenerateResponse
fetched: 2026-11-14
authority: source
ref: github.com/crowdsecurity/crowdsec@e20782bb3c532f0b9b9a469c0bdaa003588ec8e5:pkg/appsec/appsec.go
---

Constants (lines 97-102): BanRemediation = "ban", CaptchaRemediation = "captcha", AllowRemediation = "allow", ChallengeRemediation = "challenge".

Build (lines 1052-1067): DefaultPassAction defaults to allow, DefaultRemediation defaults to ban. `case BanRemediation, CaptchaRemediation, AllowRemediation, ChallengeRemediation: // those are the officially supported remediation(s)`; default branch only logs a warning "ensure bouncer compatibility!".

At tag v1.6.0 the same switch read `case "ban", "captcha", "log": //those are the officially supported remediation(s)`.

BodyResponse JSON: action, http_status, user_body_content (omitempty), user_cookies (omitempty), user_headers (omitempty).

GenerateResponse (lines 2065-2110):
- allow → http_status = UserPassedHTTPCode; bouncer status = BouncerPassedHTTPCode.
- challenge → copies UserHTTPBodyContent, cookies, UserHeaders (adds default CSP when missing), then falls through to the ban/captcha status logic.
- ban, captcha → http_status = UserHTTPResponseCode, else UserBlockedHTTPCode (default 403); bouncer status = BouncerHTTPResponseCode, else BouncerBlockedHTTPCode. No body, cookies or headers.
- default ("Custom remediations use the same status code logic as ban/captcha") → same as ban/captcha, no body.

waf_helpers.go line 358: hook helper `SetRemediation` → `w.SetAction(state, action)`; `SetAction` (appsec.go 1624) assigns `state.Response.Action = action` with no validation.
