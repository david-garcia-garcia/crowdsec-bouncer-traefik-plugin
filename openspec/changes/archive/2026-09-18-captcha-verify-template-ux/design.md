## Context

See proposal.md — Why. Dest `Validate` posts `secret` and `response` only. `ServeHTTP` already receives `req.remoteIP` from `GetRemoteIP` / `clientRequest` and writes HTTP 400 when `Validate` returns `(false, err)`. `validateEnabledCaptchaSettings` returns nil on empty `CaptchaFilePath`. `Client.New` discards `GetTemplate` (`_`). Official hCaptcha / reCAPTCHA / Turnstile siteverify all accept form field `remoteip` (`knowledge/research/ext_*_siteverify/`). Grace stays `crowdsec_captcha_gate`.

## Goals / Non-Goals

**Goals:**
- Reuse the `remoteIP` already on `ServeHTTP`. Add it to `Validate` only. POST `remoteip` with `secret` and `response`.
- Keep transport and JSON decode as `(false, err)`. ServeHTTP logs and re-renders the 200 challenge.
- When provider is set, fail empty or unloadable `CaptchaFilePath` at `ValidateParams`. Return the `GetTemplate` error from `Client.New`.

**Non-Goals:**
- A second address parse in captcha. Captcha state on `clientRequest`.
- Siteverify HTTP status on a received body (other ticket).
- Gate cookie format, Secure, `CaptchaGateSecret`, bind-IP.
- `cache.Client.Set`, `remoteIP+_captcha`, `cacheClient` on `Client.New` (declined #28).
- Bundled default template. HTML-path deprecation removal (#100).
- LAPI, AppSec, Range, Redis TTL. Importing traefik-modsecurity.
- Ban template "when path is set". #94 `mime.ParseMediaType` / `application/json` type-token rule.

## Decisions

1. **Owner of `remoteip` is `GetRemoteIP` / `clientRequest.remoteIP`.** `ServeHTTP` already has that string. Thread it into `Validate(r, remoteIP)` and `body.Add("remoteip", remoteIP)`. Do not walk forwarded headers in captcha. Alternative: parse `X-Forwarded-For` in Validate — rejected; a peer reconstruction is not the owner. Alternative: put captcha state on `clientRequest` — rejected; one extra field on this short path stays a parameter.

2. **Always `Add` the passed `remoteIP` string.** Captcha is reached only after GetRemoteIP succeeds. Do not omit the field when the string is empty. Do not send `sitekey` or `idempotency_key`. Custom provider uses the same three fields.

3. **Keep `(false, err)` for transport and JSON decode.** ServeHTTP stops writing `StatusBadRequest` and falls through to the existing 200 challenge render (same as `(false, nil)`). Alternative: return `(false, nil)` from Validate — rejected; the failure stays classified for the log. Alternative: bare 400 — rejected; Desired is retryable challenge UX.

4. **Empty captcha path fails on the same provider-set trigger as site/secret/gate.** Remove the `CaptchaFilePath == ""` early return. Then `GetTemplate`. Ban path stays optional. Error text: `CaptchaFilePath: cannot be empty when CaptchaProvider is set`. `Client.New` keeps `GetTemplate` and returns that error. Alternative: bundled default template — rejected. Alternative: fail only at `Client.New` — rejected; `New` must not open LAPI.

5. **Tests that blank `CaptchaFilePath` get a temp readable `captcha.html`**, same pattern as `pkg/captcha/zzz_servehttp_test.go`. Empty site/secret fixtures still fail on the key error; they also get a loadable path so the new rule is not the only error. Delete `knowledge/debt/2026-09-18-captcha-nil-template-panic.md` when apply lands.

## Risks / Trade-offs

- [Operators who set a provider and blank `captchaFilePath` now fail at startup] → intended fail-closed. Default `/captcha.html` is unchanged.
- [A down provider now re-renders 200 instead of 400] → solver can retry; logs still name the transport/decode error.

## Migration Plan

None for operators on the default path. Roll back by reverting the three leftovers. Apply deletes the nil-template debt file.

## Open Questions

None — ticket decisions stand on `devstate/explore.md`.
