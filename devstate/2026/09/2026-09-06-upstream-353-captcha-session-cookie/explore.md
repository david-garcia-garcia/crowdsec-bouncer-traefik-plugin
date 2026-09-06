# Explore
IssueKey: 2026-09-06-upstream-353-captcha-session-cookie

## Concepts

**Captcha grace:** After `pkg/captcha.Client.Validate` succeeds, `ServeHTTP` stores `cache.CaptchaDoneValue` (`d`) under `{remoteIP}_captcha` for `CaptchaGracePeriodSeconds` (default 1800). `Check(remoteIP)` treats that marker as “already solved” and the bouncer calls `handleNextServeHTTP` instead of re-serving the challenge.

**Client address owner:** `pkg/ip.GetRemoteIP` via `clientRequest.remoteIP`. Captcha already receives that string. Do not parse `RemoteAddr` or X-Forwarded-For again in `pkg/captcha`. `clientRequest` must not grow captcha state (`knowledge/devdocs/core_plugin_ip.md`).

**AppSec challenge cookies:** `decision.UserCookies` relayed as `Set-Cookie` (`__crowdsec_challenge` in tests). Separate path from LAPI/plugin-native captcha. Do not parse or reuse that cookie for grace.

```
  DestBranch today
  ┌──────── solve POST ─────────┐
  │ Validate OK                 │
  │ cache Set ip+"_captcha"="d" │
  │ 302 to r.URL                │
  └──────────────┬──────────────┘
                 ▼
  later GET from any client with that IP
  Check(ip) → true  (no cookie, no UA, no proto)
```

## Decisions

- Bind grace to **IP + plugin-native session cookie**. Cache key includes the token so two NAT users can hold independent sessions. Cookie value is the token; Check looks up `{remoteIP}_captcha_{token}`.
- Cookie name is a fixed constant (`crowdsec_captcha`), not a public Traefik key. Distinct from AppSec `__crowdsec_challenge`. HttpOnly, Path=/, SameSite=Lax, MaxAge=`CaptchaGracePeriodSeconds`, Secure when `r.TLS != nil`. Host-only (no Domain).
- Generate the token with `crypto/rand` (hex). If rand fails, do not store grace and do not redirect as solved.
- `Check` takes the `*http.Request` plus `remoteIP` (still GetRemoteIP’s output). Do not put the cookie on `clientRequest`.
- Ignore leftover `{ip}_captcha` keys after upgrade: Check no longer reads them. In-flight IP-only grace re-solves. Fail closed.
- Do **not** bind user-agent or HTTP protocol in this change (upstream UPD). Chrome UA churn and h2/h1 reuse would force extra challenges. Follow-up on `issues.md`.
- No new public config. TTL stays `CaptchaGracePeriodSeconds`.
- Tests in `pkg/captcha`: shared-IP isolation; Check with cookie; Check without cookie; Check with wrong cookie. Do not change AppSec cookie relay.

## Reproduction

Throwaway `go run` against dest `pkg/captcha` (temp dir, deleted; not committed). After `cache.Set("203.0.113.10_captcha", CaptchaDoneValue, 60)`:

- `Check("203.0.113.10")` twice → both `true` (shared-IP inheritance).
- `Check("203.0.113.11")` → `false`.

`Check` has no request/cookie argument, so session isolation is impossible on DestBranch. **Reproduced.**

## Recommended shape (for propose)

```
  solve POST
  Validate OK
  token ← crypto/rand
  Set-Cookie crowdsec_captcha=token (HttpOnly, SameSite=Lax, …)
  cache Set remoteIP+"_captcha_"+token = CaptchaDoneValue, grace TTL
  302

  later request
  token ← Cookie crowdsec_captcha
  missing/forged/expired → captcha page
  cache Get remoteIP+"_captcha_"+token == d → next
```

Owner of IP remains GetRemoteIP. Owner of the session token is `pkg/captcha`. Bouncer keeps passing `req.remoteIP` and `req.Request`.

## Open questions

- Q: Who already owns the client address, user-agent, and protocol for captcha grace?
  Decision: assumed — IP is `pkg/ip.GetRemoteIP` (`req.remoteIP`); reuse that string. User-agent and protocol live on `*http.Request`; this change does not store them. The session token is new and owned by `pkg/captcha` (Set-Cookie / Cookie). Do not reconstruct IP from the cookie.
  By: explore

- Q: Cookie name, Secure/HttpOnly/SameSite/Path, and whether v1 adds public Traefik keys?
  Decision: assumed — name `crowdsec_captcha`; HttpOnly; Path=/; SameSite=Lax; MaxAge=grace seconds; Secure iff `r.TLS != nil`; no Domain; no new config keys.
  By: explore

- Q: Does v1 also bind user-agent and HTTP protocol as in the upstream UPD?
  Decision: assumed — no. IP+cookie is the primary ask. UA/proto binding is a follow-up (`issues.md`).
  By: explore

- Q: Cache key shape and existing `{ip}_captcha` = `d` entries after upgrade?
  Decision: assumed — key `{remoteIP}_captcha_{token}`; value stays `CaptchaDoneValue`. Old IP-only keys are unread (re-solve). Do not migrate Redis values.
  By: explore
