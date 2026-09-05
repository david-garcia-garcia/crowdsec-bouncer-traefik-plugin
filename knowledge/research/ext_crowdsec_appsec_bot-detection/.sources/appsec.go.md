---
url: https://github.com/crowdsecurity/crowdsec/blob/cc76dbbce40bd2e6a3ce1ba07e3c41d8b462de66/pkg/appsec/appsec.go
title: pkg/appsec/appsec.go BodyResponse and challenge dispatch
fetched: 2026-09-05
authority: source
ref: github.com/crowdsecurity/crowdsec@cc76dbbce40bd2e6a3ce1ba07e3c41d8b462de66:pkg/appsec/appsec.go
---

ChallengeRemediation = "challenge". Submit JSON constants: bodyChallengeOK `{"status":"ok"}`, bodyChallengeFailed `{"status":"failed"}`, bodyChallengeRejected `{"status":"rejected"}` (reason logged, not echoed).

BodyResponse JSON: action string, http_status int, user_body_content string omitempty, user_cookies []string omitempty, user_headers map[string][]string omitempty.

GenerateResponse: allow → BouncerPassedHTTPCode (default 200). challenge copies UserHTTPBodyContent, UserHTTPCookies via cookie.String(), UserHeaders, injects DefaultChallengeCSP if CSP missing, then falls through with ban/captcha status logic: UserHTTPResponseCode or UserBlockedHTTPCode (default 403); bouncer code BouncerHTTPResponseCode or BouncerBlockedHTTPCode (default 403).

setChallengeResponse: action challenge, SetHTTPCode(user code), BouncerHTTPResponseCode = BouncerBlockedHTTPCode, body/headers/optional cookie.

Dispatch: pow-worker.js and fpscanner.js GET → setChallengeResponse StatusOK + JS. POST submit: validate; fail → failed JSON StatusOK; RejectSubmission → rejected JSON; else ok JSON + cookie. All still bouncer 403.

GrantChallengeCookie (pre_eval/post_eval): mint allowlist cookie, 307 Location=RequestURI, kind granted. GrantAllowlistCookieInline (submit): cookie on existing envelope, no 307.

Build defaults: BouncerBlockedHTTPCode 403, BouncerPassedHTTPCode 200, UserBlockedHTTPCode 403, UserPassedHTTPCode 200.
