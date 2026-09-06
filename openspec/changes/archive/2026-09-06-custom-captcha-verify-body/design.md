## Context

See proposal.md — Why. `Validate` always uses `httpClient.PostForm` with `secret` and `response`. Custom knobs already cover JS URL, validate URL, widget class, and the browser form field name. Cap Standalone siteverify is JSON with those same keys (`knowledge/research/ext_capjs_siteverify/`). Client IP is owned by `pkg/ip.GetRemoteIP`; captcha does not reconstruct it.

## Goals / Non-Goals

**Goals:**
- Custom verify can send JSON or form `secret`/`response`.
- Default empty/`form` preserves Wicketkeeper and built-in providers.
- Tests prove both encodings.

**Non-Goals:**
- Extra body fields, headers, or `remoteip`.
- Built-in CapJS widget / `cap-widget` template.
- URL templating of `CaptchaSiteKey` into the validate URL.
- Changing Wicketkeeper example stack to its official `token`/`nonce`/`response` JSON.
- Changing hCaptcha / reCAPTCHA / Turnstile verify.

## Decisions

1. **Public enum `CaptchaCustomValidateBody` with values `form` and `json`.** Empty means `form`. Alternative: MIME Content-Type string — rejected; typos. Alternative: auto-detect from URL — rejected; not every JSON provider is CapJS.

2. **Apply `json` only when `captchaProvider` is `custom`.** Built-in providers always `PostForm`. A leftover `json` on an hCaptcha route is ignored (not a ValidateParams error).

3. **Outbound keys stay `secret` and `response`.** `CaptchaCustomResponse` remains the browser form field (CapJS operators set `cap-token`). Alternative: a second mapping for the siteverify JSON key — rejected; Cap and reCAPTCHA both use `response`.

4. **Operator puts the CapJS site key in `CaptchaCustomValidateURL`.** No templating. Cap docs use `https://<instance>/<site_key>/siteverify`.

5. **`json` path: `json.Marshal` + `http.NewRequest(POST)`** (same as `pkg/lapi/client_http.go`). Decode `success` as today. Drain/close the body.

6. **Store the body format on `infoProvider` for custom; built-in entries stay form.** `Client.New` takes one extra string from bouncer config.

7. **Identity:** grace-cache key still uses the `remoteIP` `ServeHTTP` already received from the bouncer. Do not send `remoteip` on siteverify (Cap ignores it).

## Risks / Trade-offs

- [Operators omit `json` and CapJS still fails] → README and custom-captcha example document the knob and `cap-token`.
- [Yaegi] → `encoding/json` and `http.NewRequest` are already used in-tree.
- [Wicketkeeper official JSON mismatch] → out of scope; form default keeps current example behavior.

## Migration Plan

Plugin version bump. Existing custom configs omit the key and keep form. CapJS operators set `captchaCustomValidateBody: json` and `captchaCustomResponse: cap-token`. Rollback: previous tag always form.
