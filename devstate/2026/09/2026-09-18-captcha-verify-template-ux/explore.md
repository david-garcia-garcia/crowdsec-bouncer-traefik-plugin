# Explore

## Concepts

Three leftovers on dest captcha, not a new provider and not a gate-cookie rewrite.

```
GetRemoteIP ──► clientRequest.remoteIP (canonical after parse)
                      │
                      ▼
              captcha.ServeHTTP(rw, r, remoteIP)
                      │
                      ├─ today: Validate(r) POSTs secret+response only
                      └─ leftover: Validate(r, remoteIP) also POSTs remoteip
```

**remoteip owner.** `pkg/ip.GetRemoteIP` owns the client address. `bouncer.clientRequest` holds that address (`ipAddr`, `ipType`, `remoteIP`). After a successful parse, `ServeHTTP` sets `req.remoteIP = req.ipAddr.String()` before lookup, live memo, or captcha bind. Captcha already receives that string on `ServeHTTP` and `Check`. Captcha does not walk `X-Forwarded-For`. `core_plugin_ip` Language already names GetRemoteIP and clientRequest. A peer library that reconstructs the same field is not the owner.

Captcha is reached only after GetRemoteIP succeeds and `ipAddr` is non-nil. A GetRemoteIP or parse failure bans on the tech path and never calls `Validate`.

**Siteverify form.** Dest `Validate` posts `secret` and `response` only (`pkg/captcha/captcha.go`). Official contracts:

- hCaptcha: form POST; `remoteip` recommended; error codes `missing-remoteip` / `invalid-remoteip` exist. `knowledge/research/ext_hcaptcha_siteverify/`
- reCAPTCHA: POST; `remoteip` optional. `knowledge/research/ext_recaptcha_siteverify/`
- Turnstile: form or JSON POST; `remoteip` optional. `knowledge/research/ext_cloudflare_turnstile_siteverify/`

All three accept the field name `remoteip`. Custom provider uses the same `PostForm` body against an operator URL.

**Retryable provider errors.** `PostForm` error returns `(false, err)`. JSON `Decode` error returns `(false, err)` with no Validate log. `ServeHTTP` logs and writes bare HTTP 400 with no body. Empty token, `success:false`, and non-JSON Content-Type already return `(false, nil)` and re-render captcha HTML at 200. Siteverify HTTP status on a received body is another ticket.

**Loadable template.** Default `CaptchaFilePath` is `/captcha.html` (non-empty), so `validateEnabledCaptchaSettings` already runs `GetTemplate` on the default. The gap is the empty-path early return plus `Client.New` discarding `GetTemplate` error (`_`). `GetTemplate("")` errors `no template file provided`. `bouncer.New` already returns `captcha.Client.New` error. Debt `knowledge/debt/2026-09-18-captcha-nil-template-panic.md` already records this leftover; this ticket takes it. Config spec still says validate captcha/ban templates "when paths are set". Tests blank `CaptchaFilePath` to skip the file read (including "Captcha LAPI action with provider").

**Do not reuse PR #28.** Dest grace is HMAC cookie `pkg/captcha/gate.go`. `cache.Client.Set` is void. `Client.New` has no `cacheClient`. Owner declined #28 because it replaced the gate cookie with Redis `Set(remoteIP+_captcha)` and handled `cache.Set` error.

Packets consumed: `core_plugin_ip`, `core_plugin_middleware`, `core_plugin_middleware_captcha-siteverify`, `core_plugin_middleware_captcha-gate`, `core_plugin_middleware_captcha-routing`, `core_plugin_middleware_config-validation`. No Language write: terms already have owners. Usage still matches dest; propose/devdocsimpact update siteverify (remoteip + 200 on transport/decode) and config-validation (captcha template required when provider is set).

No comments.md. Qualify: qualified-with-gaps. Unattended: every Q has a Decision.

## Decisions

- Reuse `req.remoteIP` already passed into `ServeHTTP`. Thread it into `Validate(r, remoteIP)`. Add form field `remoteip` with `secret` and `response`. Do not parse forwarded headers in captcha. Do not put captcha state on `clientRequest`.
- Keep Validate errors classified: transport and JSON decode still return `(false, err)`. ServeHTTP logs and re-renders captcha HTML at 200. Do not bare-400 those. Keep `(false, nil)` for empty token, `success:false`, and non-JSON Content-Type.
- When `CaptchaProvider` is set, `ValidateParams` fails if `CaptchaFilePath` is empty or `GetTemplate` fails. `Client.New` returns the `GetTemplate` error. No bundled template. Ban template stays "when path is set".
- Tests that blank `CaptchaFilePath` to skip `GetTemplate` get a real readable file (temp fixture, same pattern as `pkg/captcha/zzz_servehttp_test.go`).
- Keep dest gate cookie, void `cache.Set`, #94 Content-Type rule, and `Client.New` without cache. Do not reuse declined PR #28.
- Fold leftovers onto `core_plugin_middleware_captcha-siteverify` and `core_plugin_middleware_config-validation`. FindSpecHost at propose. Do not fold into captcha-gate or captcha-routing.
- This ticket takes `knowledge/debt/2026-09-18-captcha-nil-template-panic.md`. Delete that file when apply lands the constructor/validation fail.

## Open questions

- Q: Who already owns the client address that siteverify `remoteip` must send?
  Decision: resolved — `pkg/ip.GetRemoteIP` owns the client address. After a successful parse, `bouncer.clientRequest.remoteIP` is `ipAddr.String()` and is the request-path spelling. `captcha.ServeHTTP` and `Check` already receive that string. Reuse that output as form `remoteip`. Do not re-parse `X-Forwarded-For`, `X-Real-Ip`, or `RemoteAddr` in captcha. A peer library that reconstructs the same field is not the owner.
  By: explore

- Q: Should captcha grow a second address type, or keep `remoteIP` as a parameter on Validate?
  Decision: assumed — keep the parameter. ServeHTTP already takes `remoteIP`; add it to Validate only. One extra field on this short path stays a parameter. Do not put captcha state on `clientRequest`.
  By: explore

- Q: Which siteverify form fields does this change send?
  Decision: assumed — `secret`, `response`, and `remoteip` only. Always `Add` the passed `remoteIP` string (canonical on the request path). Do not send hCaptcha `sitekey` or Turnstile `idempotency_key`. Custom provider uses the same three fields.
  By: explore

- Q: What happens on siteverify transport or JSON decode failure?
  Decision: assumed — Validate still returns `(false, err)` so the failure stays classified. ServeHTTP logs and re-renders captcha HTML at HTTP 200. Do not write StatusBadRequest. Empty token, `success:false`, and non-JSON Content-Type stay `(false, nil)` and the same 200 challenge.
  By: explore

- Q: Does this change inspect siteverify HTTP status on a received body?
  Decision: resolved — no. Out of scope. Other ticket. Keep dest Content-Type + `success` classification.
  By: explore

- Q: When CaptchaProvider is set and CaptchaFilePath is empty, who fails, and does that contradict "validate templates when paths are set"?
  Decision: assumed — ValidateParams fails (same provider-set trigger as site/secret/gate). Error text: `CaptchaFilePath: cannot be empty when CaptchaProvider is set`. Client.New also returns the GetTemplate error. Ban template stays "when path is set". Fold `core_plugin_middleware_config-validation`; do not invent a bundled default template.
  By: propose

- Q: How do tests that blank CaptchaFilePath keep passing?
  Decision: assumed — give those cases a readable fixture file (temp `captcha.html`, same as captcha ServeHTTP tests). Tests that assert empty site/secret still fail on the key error; they also need a loadable path so the new empty-path rule is not the only error.
  By: explore

- Q: Does this change reuse declined PR #28 (Redis Set `remoteIP+_captcha` and cache.Set error)?
  Decision: resolved — no. Keep dest HMAC gate cookie (`pkg/captcha/gate.go`). `cache.Set` stays void. Do not add `cacheClient` to `Client.New`.
  By: explore
