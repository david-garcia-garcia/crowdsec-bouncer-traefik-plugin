## Context

See proposal.md — Why. On DestBranch, `pkg/captcha.Client.ServeHTTP` stores `CaptchaDoneValue` at `{remoteIP}_captcha` and `Check(remoteIP)` reads that key only. `Bouncer.handleRemediationServeHTTP` passes `req.remoteIP` into both. AppSec `UserCookies` are a different Set-Cookie relay.

## Goals / Non-Goals

**Goals:**
- Bind plugin-native captcha grace to GetRemoteIP plus a session cookie.
- Keep multiple independent sessions per IP (NAT).
- Fail closed on missing/wrong cookie and on leftover IP-only keys.

**Non-Goals:**
- User-agent or HTTP protocol binding (upstream UPD; follow-up).
- Public Traefik keys for cookie name/TTL/flags.
- Changing AppSec challenge cookies or `Validate` / siteverify.
- Putting captcha state on `clientRequest`.

## Decisions

1. **Cookie name `crowdsec_captcha`.** Distinct from AppSec `__crowdsec_challenge`. Alternative: operator-configured name — rejected; no new public key.

2. **Cache key `{remoteIP}_captcha_{token}` with value `CaptchaDoneValue`.** Two NAT users keep independent entries. Alternative: one `{ip}_captcha` whose value is the token — rejected; the second solver would evict the first.

3. **Token from `crypto/rand`, hex.** If rand fails, do not store grace and do not redirect as solved. Alternative: HMAC of IP+expiry in the cookie with no cache — rejected; revoke/TTL already lives on the isolated cache Client.

4. **Check signature takes `*http.Request` and `remoteIP`.** IP remains GetRemoteIP’s string. Do not parse the cookie into a second IP. Do not add fields to `clientRequest`.

5. **Cookie flags:** HttpOnly, Path=/, SameSite=Lax, MaxAge=`CaptchaGracePeriodSeconds`, Secure when `r.TLS != nil`, no Domain. Alternative: always Secure — rejected; HTTP lab and e2e would never send the cookie.

6. **Old `{ip}_captcha` keys unread.** No Redis migration. Alternative: treat value `d` without a cookie as solved during one TTL — rejected; that keeps the shared-IP hole for the upgrade window.

7. **No UA/proto in the cache value.** Alternative: store UA+Proto beside the marker — rejected this change; Chrome UA churn and h1/h2 reuse would force extra challenges.

## Risks / Trade-offs

- [HTTP behind a TLS terminator] → cookie may omit Secure; operators who need Secure-only can terminate TLS on Traefik so `r.TLS` is set.
- [Copied cookie on the same IP] → still works until TTL; UA bind is the follow-up.
- [Yaegi] → stdlib `crypto/rand` / `encoding/hex` / `net/http` Cookie only; no new module.

## Migration Plan

Plugin version bump. In-flight IP-only grace re-solves once. Rollback: previous tag restores IP-only keys; new cookie keys are leftover until TTL.
