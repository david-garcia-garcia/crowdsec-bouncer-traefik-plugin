# Explore
IssueKey: 2026-09-06-upstream-318-capjs-custom-captcha

## Concepts

```
Browser POST (captcha.html)
  FormValue(CaptchaCustomResponse)  → token
        │
        ▼
pkg/captcha.Client.Validate
  today:  PostForm  secret+response  (urlencoded)
  needed: same keys, JSON body, Content-Type application/json  (CapJS)
        │
        ▼
Custom validate URL
  Wicketkeeper:  POST /v0/siteverify   application/x-www-form-urlencoded
  CapJS:         POST /<site_key>/siteverify   application/json
                 { "secret": "<CaptchaSecretKey>", "response": "<token>" }
                 → { "success": true }
```

- `Validate` always builds `url.Values` `secret`/`response` and calls `httpClient.PostForm` (`pkg/captcha/captcha.go`). Built-in hCaptcha/reCAPTCHA/Turnstile and custom share that one path.
- Custom knobs already exist: `CaptchaCustomJsURL`, `CaptchaCustomValidateURL`, `CaptchaCustomKey`, `CaptchaCustomResponse`. Site/secret keys are `CaptchaSiteKey` / `CaptchaSecretKey`.
- CapJS Standalone (https://trycap.dev/guide/standalone/) siteverify is JSON, not form. Keys match (`secret`, `response`). Response `success` already matches `responseProvider`. Widget token field is `cap-token` (operator sets `CaptchaCustomResponse`). Verify URL includes the site key in the path; `CaptchaCustomValidateURL` is already a full URL.
- Wicketkeeper example documents urlencoded-only (`examples/custom-captcha/README.md`). Default must stay form. Wicketkeeper's own `/v0/siteverify` is JSON with `token`/`nonce`/`response` (not `secret`+`response`); that mismatch is out of scope — reporter already used Wicketkeeper with today's PostForm path. See `knowledge/research/ext_capjs_siteverify/`.
- No `pkg/captcha/*_test.go`. No captcha spec family (`openspec/specs/map.md` plugin components: appsec, decisions, ip, lapi, middleware). No captcha usage packet (`knowledge/devdocs/index_core_plugin.md`).
- Client IP is already chosen by `pkg/ip.GetRemoteIP` on the bouncer; `Validate` does not use it. CapJS siteverify does not require `remoteip`.

## Decisions

- **Config knob:** Add `CaptchaCustomValidateBody` (`json:"captchaCustomValidateBody,omitempty"`). Allowed: empty/`form` (current `PostForm`) and `json` (`POST` with `Content-Type: application/json` and `{"secret","response"}`). Reject any other value at `validateCaptcha`. Empty default so existing Wicketkeeper and built-in providers stay unchanged.
- **Who uses it:** Only `captchaProvider=custom`. Built-in providers keep `PostForm` regardless of the field. Non-empty value with a non-custom provider is ignored (not an error) so leftover labels do not break hCaptcha routes.
- **Outbound keys:** Always `secret` and `response` to the provider. `CaptchaCustomResponse` remains the browser-form field name only (CapJS operators set `cap-token`). Do not add a second mapping for the siteverify JSON key.
- **Validate URL:** Operator puts the CapJS site key in `CaptchaCustomValidateURL` (`https://<instance>/<site_key>/siteverify`). No URL templating from `CaptchaSiteKey`.
- **No extra fields/headers/`remoteip`:** Ticket minimum is JSON vs form. Do not invent a header map or extra body keys.
- **Implementation:** On `json`, `json.Marshal` + `http.NewRequest(POST, …)` (same pattern as `pkg/lapi/client_http.go`). Drain/decode `success` as today. `New` grows one body-format argument; bouncer passes the config field.
- **Tests:** `pkg/captcha/captcha_test.go` with `httptest` — custom `form` posts urlencoded `secret`/`response`; custom `json` posts JSON with those keys and `application/json`; built-in still urlencoded; missing token / non-POST still skip verify.
- **Docs:** README config list + `examples/custom-captcha/README.md` note that verify may be form (Wicketkeeper) or JSON (CapJS). No new CapJS docker stack in this change.
- **Spec:** New leaf `core_plugin_captcha_custom-verify` (family `core_plugin_captcha`). No existing captcha spec to fold onto.
- **Identity:** Reuse `pkg/ip.GetRemoteIP` output already on the bouncer request. Do not reconstruct IP inside captcha. Do not send `remoteip` on siteverify.

## Open questions

- Q: Enum name (`form`/`json`) vs a MIME Content-Type string vs auto-detect from the validate URL?
  Decision: resolved — `form`/`json` enum on `CaptchaCustomValidateBody`; default empty=`form`. MIME strings invite typos; URL auto-detect is wrong for any JSON provider not named CapJS.
  By: explore

- Q: Does CapJS token field need a separate mapping from `CaptchaCustomResponse`?
  Decision: resolved — no. Widget posts `cap-token`; operator already sets `CaptchaCustomResponse`. Outbound siteverify key stays `response`.
  By: explore

- Q: Who owns the client address for captcha verify?
  Decision: resolved — `pkg/ip.GetRemoteIP` on the bouncer; captcha `ServeHTTP` already receives `remoteIP` for grace cache only. CapJS siteverify does not require `remoteip`; do not reconstruct or add it here.
  By: explore

- Q: Should `json` apply to built-in providers?
  Decision: resolved — no. hCaptcha/reCAPTCHA/Turnstile stay `PostForm`. The knob is custom-only.
  By: explore

- Q: Extra verify fields/headers (ticket “more control”)?
  Decision: assumed — out of scope this change; JSON vs form is enough for CapJS Standalone. Follow-up if another provider needs more.
  By: explore
