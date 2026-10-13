Captcha siteverify remoteIP, retryable provider errors, and required template when CaptchaProvider is set.

Leftovers only:

1) Siteverify must send bouncer-resolved remoteIP as form field remoteip together with secret and response. Thread remoteIP from ServeHTTP into Validate(r, remoteIP). Do not re-parse X-Forwarded-For inside captcha.

2) Provider transport errors and JSON decode failures are retryable: log and re-render captcha HTML with HTTP 200. Do not return bare HTTP 400 for those. success:false and empty token stay (false, nil) and already re-render 200. Non-JSON Content-Type already returns (false, nil) on master after #94 — keep that as 200 re-render, not 400.

3) When CaptchaProvider is set, require a loadable captcha template: ValidateParams fails if CaptchaFilePath is empty or GetTemplate fails. Client.New must return GetTemplate error (today it discards with _). Default config CaptchaFilePath is /captcha.html — empty path is the gap. Do not invent a bundled template.

Current dest (do not regress):
- Grace is crowdsec_captcha_gate cookie (mintGateValue / setGateCookie / Check). ServeHTTP on success sets cookie then 302. Keep that.
- cache.Client.Set stays void. Redis errors stay logged inside redisCache.set.
- Validate Content-Type uses the current #94 rule (mime / application/json prefix as on master) — do not revert to strings.Contains.
- Client.New signature has no cacheClient (gate cookie). Do not add cache back to captcha.Client.

Bound: do not change cache.Set API. Do not write remoteIP+_captcha. Do not change gate cookie format, Secure, or CaptchaGateSecret. Do not touch LAPI, AppSec, Range, Redis TTL, or HTML-path deprecation removal (#100). Do not import traefik-modsecurity.

Do not reuse closed PR #28 or branch 2026-09-06-captcha-handler-hardening. Owner declined that PR: it rewrote grace as Redis Set(remoteIP+_captcha) and made cache.Client.Set return error. Master already uses HMAC cookie pkg/captcha/gate.go.

Tests expected later (do not implement in prepare):
- siteverify POST body includes remoteip
- transport error ServeHTTP is 200 captcha HTML not 400
- New/ValidateParams fail on empty or missing template when provider set
- success still 302 + Set-Cookie
