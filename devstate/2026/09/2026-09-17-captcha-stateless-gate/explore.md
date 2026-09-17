# Explore
IssueKey: 2026-09-17-captcha-stateless-gate

## Concepts

**Captcha gate cookie**:
HttpOnly cookie issued after a successful provider verify. Value is a versioned payload plus HMAC-SHA256. `Check` treats a valid cookie as grace. No cache key.

**Bind-IP mode**:
Payload includes the client address `pkg/ip.GetRemoteIP` already chose (`req.remoteIP`). Validation also requires that string to match. Default.

**Cookie-only mode**:
HMAC + expiry only. IP in the payload is ignored (or omitted). Operator knob.

**Gate secret**:
Dedicated HMAC key (`captchaGateSecret` / file). Not `CaptchaSecretKey` (provider siteverify).

## Decisions

- Grace leaves the cache. `pkg/captcha` drops `*cache.Client`, `{ip}_captcha`, and `CaptchaDoneValue`. Leftover cache keys do not pass `Check`.
- `Check` takes `*http.Request` plus `remoteIP` from `clientRequest` (do not call `GetRemoteIP` again).
- `ServeHTTP` already has `r` and `remoteIP`; on solve it `Set-Cookie` then 302.
- PR #45 closed without merge (comment points at #58). Do not take its token-in-cache design.
- `core_cache_client_isolated-store` captcha-grace requirement is removed or rewritten in propose (cache no longer stores `d`).
- Captcha stays on Bouncer. No reclaim change.

## Open questions

- Q: Who already owns the client address for captcha grace?
  Decision: resolved — `pkg/ip.GetRemoteIP` owns it; bouncer stores it on `clientRequest.remoteIP`. Captcha compares that string (and, when binding, the same string signed in the cookie). Do not re-parse `RemoteAddr` or XFF in captcha.
  By: explore

- Q: Cookie name, attributes, and whether v1 adds public Traefik keys for them?
  Decision: assumed — name `crowdsec_captcha_gate`; HttpOnly; Path=/; SameSite=Lax; MaxAge=grace seconds; Secure iff `r.TLS != nil`; no Domain; no public keys for name/flags.
  By: explore

- Q: Public knob for bind-IP vs cookie-only, and dedicated HMAC secret field?
  Decision: assumed — `captchaGateBindIP` bool default true; `captchaGateSecret` + `captchaGateSecretFile` via existing `GetVariable`. Empty secret when captcha is enabled is rejected at ValidateParams. Do not derive from `CaptchaSecretKey` or LAPI key.
  By: explore

- Q: Payload encoding and expiry?
  Decision: assumed — compact `v1.<unix_issued>.<0|1>.<ip>` + `.` + base64url HMAC-SHA256 of that prefix; expiry is `issued + CaptchaGracePeriodSeconds`; 30s clock skew allowed on the low side. Cookie-only still writes `0` and empty ip. Compare HMAC with `hmac.Equal`.
  By: explore

- Q: IPv6 normalization when comparing bound IP?
  Decision: assumed — compare `req.remoteIP` to the payload ip as opaque strings. `GetRemoteIP` already chose the hop string; captcha does not call `net.ParseIP.String()`.
  By: explore

- Q: Does captcha still need cache for anything?
  Decision: resolved — no. Provider verify is HTTP; grace is the cookie. Drop cache from `New` and bouncer wiring (`lapiClient.Cache()`).
  By: explore

- Q: UA / proto bind as in upstream #353 UPD?
  Decision: resolved — no; out of scope.
  By: explore
