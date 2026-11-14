---
url: https://github.com/crowdsecurity/crowdsec/blob/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c/pkg/appsec/appsec.go
title: pkg/appsec/appsec.go hook build, status defaults, GenerateResponse
fetched: 2026-11-14
authority: source
ref: github.com/crowdsecurity/crowdsec@3d369d64eb3e9ba770ed39aedc83ffd3170aef4c:pkg/appsec/appsec.go
---

`Hook.Build`: `if stage == hookPreEval { opts = append(opts, rateLimitExprOptions...) }` -> `RateLimit` only compiles in `pre_eval`.

`HookOutcome` comment: an allow outcome produces neither event nor alert, "and neither does RateLimit's ban, which emits its own".

Config keys: `blocked_http_code` -> `BouncerBlockedHTTPCode` ("returned to the bouncer"); `user_blocked_http_code` -> `UserBlockedHTTPCode` ("returned to the user"). Both default to `http.StatusForbidden` (403) when 0.

YAML keys `inband` / `outofband` (`AppsecPhaseConfig`, each with `pre_eval`) plus legacy top-level `pre_eval`. The same keys exist at `v1.8.0` (raw `v1.8.0/pkg/appsec/appsec.go`, lines 349, 553, 562-563).

`ret.RateLimits = newRateLimits(wc.Name, patcher.RateLimits)`: limiters per AppSec engine, built from the collected calls.

`GenerateResponse`, case `BanRemediation` / `CaptchaRemediation`: `resp.HTTPStatus = response.UserHTTPResponseCode` (fallback `UserBlockedHTTPCode` if 0); `bouncerStatusCode = response.BouncerHTTPResponseCode` (fallback `BouncerBlockedHTTPCode`). `BodyResponse` JSON keys `action`, `http_status`.
