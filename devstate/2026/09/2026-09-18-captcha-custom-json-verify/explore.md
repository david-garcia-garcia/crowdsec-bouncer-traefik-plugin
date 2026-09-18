# Explore

## Concepts

Dest `Client.Validate` always `PostForm`s urlencoded `secret`+`response`. Cap Standalone wants JSON. The first-hop browser field is already `captchaCustomResponse` (`cap-token`). This ticket is the second-hop body encoding only.

```
browser POST  ──captchaCustomResponse (cap-token)──►  Validate
                                                         │
                         dest today: PostForm secret+response
                         desired:    form | json (custom-only)
                                                         ▼
                                              provider /siteverify
                                              reply Siteverify JSON + success
                                                         ▼
                                         mintGateValue / setGateCookie / 302
```

**Cap Standalone contract** (`knowledge/research/ext_capjs_standalone_siteverify/`): `POST https://<instance>/<site_key>/siteverify`, `Content-Type: application/json`, `{"secret","response"}`, reply `{ "success": true }`. Official pages do not list request `remoteip`. Widget default field is `cap-token`. Marketing says reCAPTCHA-compatible; every official request example is JSON, not urlencoded.

**Dest Validate** (`pkg/captcha/captcha.go`): signature `(r *http.Request)` only. No `remoteip` field. `ServeHTTP(rw, r, remoteIP)` already has the bouncer address for the gate cookie, then calls `Validate(r)` without it. Siteverify reply already uses `mime.ParseMediaType` (archived `captcha-siteverify-content-type-case` is on dest). Requirement Current that said `HasPrefix` / no siteverify spec is stale.

**Identity owner.** `pkg/ip.GetRemoteIP` owns the client address. `bouncer.clientRequest.remoteIP` is that address after parse (`ipAddr.String()`). Captcha already receives it on `ServeHTTP` / `Check`. Captcha does not walk forwarded headers. Sibling `2026-09-18-captcha-verify-template-ux` worktree has `Validate(r, remoteIP)` and always `Add("remoteip", remoteIP)` — not on dest, implement Work still `[ ]`. This run does not invent `remoteip` on current dest.

**Built-in vs custom knobs.** `validateCaptcha` requires the four custom strings only when provider is `custom`. Built-in providers ignore `CaptchaCustomChallengeURL` (startup still succeeds). Ticket Desired says reject `json` when provider is not custom; the test bullet also allowed ignore. This explore picks reject.

**Out of scope (do not do).** `captchaProvider: trycap`, `captchaTrycapInstanceUrl`, `<cap-widget>` template branch. Extra verify fields/headers. Template-required and 200-on-retryable leftovers (sibling ticket). Split HTTP timeouts, backendbackoff, LAPI/AppSec/Range/module path. Closed PR #52 / branch `2026-09-06-upstream-318-capjs-custom-captcha`. Closed PR #40 trycap provider. Do not retarget Wicketkeeper `examples/custom-captcha` to JSON. Do not change `cache.Client.Set` or dest gate cookie.

Packets consumed: `core_plugin_ip`, `core_plugin_middleware_captcha-siteverify`, `core_plugin_middleware_captcha-gate`, `core_plugin_middleware_captcha-routing`, `core_plugin_middleware_config-validation`. Research: `ext_http_media-types` (reply classification already owned); wrote `ext_capjs_standalone_siteverify`. No Language/usage write: existing siteverify packet still matches dest reply classification; request encoding does not exist yet.

No comments.md. Qualify: qualified-with-gaps. No active OpenSpec change. Nested Task was unavailable this worker; CapJS research was written on this thread from official trycap.dev pages.

## Decisions

- Optional `captchaCustomValidateBody` / `CaptchaCustomValidateBody`: `""` or `"form"` = today's `PostForm`; `"json"` = `POST application/json` object with `secret` and `response`. Same dest `httpClient`. Do not split timeouts.
- Knob is custom-only. Built-in hcaptcha/recaptcha/turnstile always `PostForm`.
- `ValidateParams` rejects `json` when provider is not `custom`. Rejects unknown values for any provider. Built-in leftover `""` / `"form"` is ignored (same shape as ignoring `CaptchaCustomChallengeURL`).
- Default omit keeps Wicketkeeper `examples/custom-captcha` on urlencoded. Do not retarget that example.
- README documents the knob and a CapJS **custom** example (validate URL + `cap-token` + `json`). No new provider. No `<cap-widget>` template branch.
- Do not invent `remoteip` on current dest (`Validate(r)` has no IP). Implement syncs `origin/master` and absorbs only if dest then threads `remoteIP` into `Validate`; then include `remoteip` on both encodings when non-empty. Owner is GetRemoteIP / `clientRequest.remoteIP`, already on `ServeHTTP`.
- Keep dest siteverify reply `mime.ParseMediaType` + `success`, gate cookie + 302, void `cache.Set`.
- Store the encoding on `Client` (custom-only, sibling of `challengeURL`), not the shared `infoProviders` map. `bouncer.New` passes the config string into `Client.New`.
- Propose runs FindSpecHost. Do not rename `core_plugin_middleware_captcha-siteverify`. Likely fold request encoding onto that leaf and the knob onto `core_plugin_middleware_config-validation`.

## Open questions

- Q: Who already owns the client address if this change would send siteverify `remoteip`?
  Decision: resolved — `pkg/ip.GetRemoteIP` owns the client address. After a successful parse, `bouncer.clientRequest.remoteIP` is `ipAddr.String()`. `captcha.ServeHTTP` and `Check` already receive that string. Dest `Validate(r)` has no IP. Sibling `2026-09-18-captcha-verify-template-ux` threaded `Validate(r, remoteIP)` only on its branch (not dest). Do not invent `remoteip` on current dest. Implement syncs `origin/master` and absorbs only if dest then has that argument; then add `remoteip` on form and JSON when non-empty. Do not re-parse forwarded headers in captcha.
  By: explore

- Q: Built-in provider plus `captchaCustomValidateBody: json` — ignore the knob or reject at ValidateParams?
  Decision: resolved — ValidateParams rejects `json` when provider is not `custom`. Built-ins always `PostForm`. `""` / `"form"` on a built-in is ignored. Unknown values fail for any provider. Test the reject path.
  By: explore

- Q: Which strings does `CaptchaCustomValidateBody` accept?
  Decision: assumed — after trim: `""`, `form`, `json` (exact lowercase). `JSON` / `Form` / other tokens fail as unknown. Document lowercase in README.
  By: explore

- Q: Does Cap Standalone document request `remoteip`?
  Decision: resolved — no. Official JSON is `secret` and `response` only (`knowledge/research/ext_capjs_standalone_siteverify/`). Extra fields stay out of scope except absorb-only `remoteip` if dest later threads the address.
  By: explore

- Q: Add `captchaProvider: trycap`, `captchaTrycapInstanceUrl`, or a `<cap-widget>` template branch?
  Decision: resolved — no. Custom provider + `cap-token` + `json` body. Operator HTML stays theirs.
  By: explore

- Q: Reuse closed PR #52 / branch `2026-09-06-upstream-318-capjs-custom-captcha` or closed PR #40 trycap provider?
  Decision: resolved — no. Upstream #318 is context only. Do not restore cache-grace Validate.
  By: explore

- Q: Where does the encoding knob live at runtime, and which spec leaf owns it?
  Decision: assumed — `Client` field filled from `CaptchaCustomValidateBody` in `Client.New` (not `infoProviders`). Propose FindSpecHost; do not rename `core_plugin_middleware_captcha-siteverify`. Likely fold request encoding there and ValidateParams rules into `core_plugin_middleware_config-validation`.
  By: explore

- Q: Dest siteverify reply still `HasPrefix`, or keep the dest `mime.ParseMediaType` rule?
  Decision: resolved — dest already classifies with `mime.ParseMediaType` (spec `core_plugin_middleware_captcha-siteverify`). Keep that hop. Do not revert to `HasPrefix`. Sibling content-type-case already landed.
  By: explore
