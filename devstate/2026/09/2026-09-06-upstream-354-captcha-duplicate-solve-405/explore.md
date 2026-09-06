# Explore
IssueKey: 2026-09-06-upstream-354-captcha-duplicate-solve-405

## Concepts

Captcha remediation has two HTTP owners:

- Unsolved: `Bouncer.handleRemediationServeHTTP` calls `captcha.Client.ServeHTTP`, which `Validate`s a POST that carries the provider response field, then `Set`s grace `remoteIP+"_captcha"` = `cache.CaptchaDoneValue` and `http.Redirect` (`StatusFound`) to `r.URL.String()`.
- Solved: the same handler `Check`s that cache key and, when true, calls `handleNextServeHTTP` with the original request (method and body unchanged). AppSec still runs on that pass path.

The bundled form POSTs to the current URL (`captcha.html` empty `action`, `captchaCallback` submits `#captcha-form`). Provider widgets inject the token under `h-captcha-response` / `g-recaptcha-response` / `cf-turnstile-response` (or `CaptchaCustomResponse` for custom). There is no dedicated captcha path.

```
tab1 POST + token  → Validate ok → Set grace → 302 GET
tab2 POST + token  → Check true  → next.ServeHTTP(POST)  → origin 405 if GET-only
```

Reproduced in a throwaway `handleRemediationServeHTTP` call (not kept): after `Set("192.0.2.10_captcha", CaptchaDoneValue)`, a POST with `h-captcha-response` returned `status=200 nextCalled=true nextMethod=POST location=` — plugin relayed POST to `next`; it did not redirect.

Laravel 405 is origin behavior after that relay. A stub `next` that rejects POST is an honest unit seam; a full Laravel stack is not required.

`FormValue` / `ParseForm` consume `req.Body`. Today that parse happens only on the unsolved path, which never forwards. A grace-path detector that `FormValue`s every POST would empty the body for legitimate origin POSTs after solve.

Client address for grace is already `clientRequest.remoteIP` (`GetRemoteIP`). Captcha state stays off that type. Captcha HTTP client and templates already live on Bouncer; this change does not add tickers or package globals.

No captcha spec leaf exists under `openspec/specs/`. No `knowledge/devdocs` captcha packet (middleware packet only says templates live on Bouncer).

## Decisions

- Fix at `handleRemediationServeHTTP` when captcha remediation, client valid, `Check(req.remoteIP)`, and the request is a captcha form POST: redirect like the first successful verify (`StatusFound` to `req.URL.String()`, `solved-captcha` remediation header when configured). Do not call `handleNextServeHTTP` on that branch (so AppSec/origin never see the duplicate token POST — same as first solve).
- Detection belongs on `captcha.Client` (it owns `infoProvider.response`). Cover hcaptcha, recaptcha, turnstile, and custom. Do not key off the config field name `CaptchaCustomResponse` alone.
- Ordinary POST/GET during grace still pass through. Only intercept POST that carries the configured provider response field.
- If the detector reads the body and does not intercept, restore `Body` before `handleNextServeHTTP` (AppSec/origin must still see the payload). Intercepted captcha POSTs may leave the body consumed.
- Do not re-call the provider on the already-solved path (ticket: skip if already solved; used tokens often fail siteverify).
- Do not change `captcha.html`.
- Prove with unit tests: bouncer grace + captcha POST → 302 and `next` not called; grace + origin POST without the field → `next` called and body intact. Captcha helper tests for method/field/provider names. No e2e Laravel.

## Open questions

- Q: Should a POST without the provider response field during grace still reach origin?
  Decision: assumed — yes; the ticket is duplicate captcha submit. Origin forms after solve must keep working.
  By: explore

- Q: How do we detect a captcha form POST without emptying origin POST bodies?
  Decision: assumed — `captcha.Client` inspects POST + configured response field; restore `Body` when not intercepting. Do not `FormValue` then forward.
  By: explore

- Q: Who already owns the client address used for the grace key?
  Decision: resolved — `clientRequest.remoteIP` from `ip.GetRemoteIP`. Reuse `Check(req.remoteIP)`. Do not re-parse `RemoteAddr`.
  By: explore

- Q: Which redirect status and header match the first successful verify?
  Decision: assumed — `http.StatusFound` to `req.URL.String()`, and `remediationCustomHeader=solved-captcha` when that header is configured (same as `captcha.Client.ServeHTTP` success).
  By: explore

- Q: Should the second tab hit the captcha provider again?
  Decision: assumed — no; grace means already solved. Re-verify would often fail on a one-time token and is not what the ticket asked.
  By: explore

- Q: Minimal test seam instead of Laravel?
  Decision: resolved — `httptest` `next` that records method/body (and can 405 on POST) plus in-memory cache grace is enough to prove relay vs redirect.
  By: explore
