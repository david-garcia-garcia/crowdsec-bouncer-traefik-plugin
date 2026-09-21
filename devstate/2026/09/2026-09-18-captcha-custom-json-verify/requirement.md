# Requirement
IssueKey: 2026-09-18-captcha-custom-json-verify

## Problem
Cap Standalone / CapJS siteverify wants `POST application/json` `{"secret","response"}`. Dest `Validate` always `PostForm` urlencoded. `captchaCustomResponse` already names the browser field (`cap-token`); the second-hop body encoding is not configurable.

## Current (code)
- `Validate(r)` always `url.Values` + `httpClient.PostForm` with `secret` and `response`. No body-encoding knob. Path: `pkg/captcha/captcha.go`.
- `Validate` signature is `(r *http.Request)` only. No `remoteIP` argument. No `remoteip` form or JSON field. Path: `pkg/captcha/captcha.go`.
- `ServeHTTP` already has `remoteIP` for `mintGateValue` / `setGateCookie` after success, then 302. Path: `pkg/captcha/captcha.go`, `pkg/captcha/gate.go`.
- Custom provider copies `js`, `key`, `response`, `validate` into `infoProvider`. No validate-body field. Path: `pkg/captcha/captcha.go`.
- Built-in hcaptcha / recaptcha / turnstile share the same `PostForm` path. Path: `pkg/captcha/captcha.go`.
- Config has `CaptchaCustomJsURL`, `CaptchaCustomValidateURL`, `CaptchaCustomKey`, `CaptchaCustomResponse`, `CaptchaCustomChallengeURL`. No `CaptchaCustomValidateBody`. Path: `pkg/configuration/configuration.go`.
- `validateCaptcha` requires the four custom strings when provider is `custom`. Does not mention a body encoding. Path: `pkg/configuration/configuration.go`.
- Built-in providers ignore `CaptchaCustomChallengeURL`. Path: `pkg/configuration/zzz_configuration_test.go`.
- README documents custom knobs and Wicketkeeper. No CapJS JSON example. Path: `README.md`.
- Wicketkeeper example states siteverify is `application/x-www-form-urlencoded`. Path: `examples/custom-captcha/README.md`.
- Siteverify reply Content-Type uses `strings.HasPrefix(..., "application/json")`. `mime.ParseMediaType` is used on the captcha template, not this hop. Path: `pkg/captcha/captcha.go`.
- `cache.Client.Set` is void. Path: `pkg/cache/cache.go`.
- No `trycap` provider constant. Path: `pkg/configuration/configuration.go`.
- No captcha-siteverify spec leaf on dest. Path: `openspec/specs/core_plugin_middleware_captcha-siteverify` (not found).
- CapJS Standalone siteverify JSON contract is not in `knowledge/research/` (indexes consumed; no Task write this phase). Ticket URL: https://trycap.dev/guide/standalone/

## Desired
- Optional `captchaCustomValidateBody` / `CaptchaCustomValidateBody`: `""` or `"form"` = today's `PostForm`; `"json"` = `POST application/json` object with `secret` and `response`.
- Knob is custom-only. Built-in providers always `PostForm`. Reject unknown values. Reject `json` when provider is not `custom`.
- Default omit keeps Wicketkeeper `examples/custom-captcha` working. Do not retarget that official JSON.
- README: document the knob and a CapJS custom example (validate URL + `cap-token` + json body).
- If dest (or a later `origin/master` sync) already threads `remoteIP` into `Validate`, include `remoteip` on both encodings when non-empty. Do not invent it on current dest.
- Keep gate cookie on success (`mintGateValue` / `setGateCookie` / 302). Keep dest siteverify Content-Type check. Do not change `cache.Client.Set`.
- Tests: custom+json sees JSON Content-Type and `secret`/`response` (plus `remoteip` only if `Validate` has it); custom+form/omit still urlencoded; unknown body fails `ValidateParams`; success still 302 + Set-Cookie; built-in+json per explore (ticket Desired already says reject).

## Affected
- `pkg/configuration/configuration.go` (`CaptchaCustomValidateBody`, `validateCaptcha`)
- `pkg/captcha/captcha.go` (`Validate` request encoding)
- `README.md`
- Captcha / configuration tests
- Possible later spec leaf for siteverify body encoding (not on dest today)

## Out of scope
- `captchaProvider: trycap`, `captchaTrycapInstanceUrl`, `<cap-widget>` template branch
- Extra verify fields or headers beyond `secret`, `response`, and absorb-only `remoteip`
- Leftovers: template required, 200-on-retryable (except absorb `remoteip` if dest already has it)
- Split HTTP timeouts, backendbackoff
- LAPI, AppSec, Range, module path
- Closed PR #52 / branch `2026-09-06-upstream-318-capjs-custom-captcha` (stale cache-grace Validate)
- Closed unmerged PR #40 trycap provider
- Changing Wicketkeeper example to JSON
- Changing `cache.Client.Set` or dest gate cookie

## Unknowns
- Official CapJS siteverify JSON is only in the ticket URL; no `knowledge/research/` extract this phase.
- Whether sibling `2026-09-18-captcha-verify-template-ux` lands `remoteIP` on dest before implement. Current dest `Validate(r)` has none.
- Whether sibling `2026-09-18-captcha-siteverify-content-type-case` lands `mime.ParseMediaType` on the siteverify hop before implement. Current dest uses `HasPrefix`.

## Tensions
- Ticket Desired says reject `json` when provider is not custom. The test bullet also allows “built-in ignores the knob” and says pick one in explore.
- Owner declined #52 as stale (cache-grace Validate). This run must not reuse that branch or restore cache grace.
- Ticket says keep #94 Content-Type rule; dest siteverify hop is still `HasPrefix`, not `mime.ParseMediaType`.
