# reCAPTCHA Enterprise

Date: 2026-09-24.

Support Google Cloud reCAPTCHA Enterprise checkbox keys and score keys. Classic `recaptcha` stays on `api.js` and `siteverify`. The request path does not branch on provider name.

## Problem

`captchaProvider=recaptcha` is classic reCAPTCHA v2. `pkg/captcha/captcha.go` hardcodes `https://www.google.com/recaptcha/api.js`, the `g-recaptcha` class, the `g-recaptcha-response` field, and `POST https://www.google.com/recaptcha/api/siteverify` with `secret`, `response`, and optional `remoteip`. A solve counts only when the JSON body has `success: true`.

A key created in the Google Cloud reCAPTCHA console (Essentials, Standard, or Enterprise) does not use that exchange. The browser loads `https://www.google.com/recaptcha/enterprise.js`. The server calls `POST https://recaptchaenterprise.googleapis.com/v1/projects/{project}/assessments` and reads `tokenProperties.valid`, then the action and the score when those are configured. Auth is a Cloud API key, not a siteverify shared secret.

A classic v2 checkbox key that Google auto-migrated into a Cloud project still works with `captchaProvider=recaptcha` and its existing secret. This change does not replace that path.

The `custom` provider cannot stand in. Its JSON body is fixed as `secret`, `response`, and `remoteip`, and the pass check only reads `success`.

## Request path

`ServeHTTP` and `Validate` do not mention a provider or a key type. Construction stores two fields on the client:

- **Widget** — data the challenge page reads: script URL, CSS class, token field name, optional action, boot script, and whether a refused token may render the puzzle again.
- **Verifier** — `Pass(token, remoteIP) (bool, error)`.

`Validate` returns three outcomes, not one boolean:

| Outcome | When |
| --- | --- |
| No token | The request is not a POST, or the token field is empty. |
| Pass | `verifier.Pass` returns true. |
| Reject | A token was posted and `verifier.Pass` returns false with no error. |
| Error | Transport failed, or the body was not decodable JSON. Same classification as siteverify today: `(false, err)`. |

`ServeHTTP`:

- Error or no token: render the challenge. The boot script runs.
- Pass: mint `crowdsec_captcha_gate`, set the remediation header to `solved-captcha`, `302` to the request URL. Unchanged.
- Reject and the widget allows retry: render the challenge again (checkbox).
- Reject and the widget does not allow retry: render the same page with the boot script omitted (score), so the browser does not call Google again.

Today `(false, nil)` means both "no token" and "provider said no". Those stay collapsed only inside the siteverify and assessment verifiers' pass bit. `Validate` itself distinguishes "no token" from "rejected" so a score refusal cannot reload into another `execute`.

## Verifiers

One interface. Two implementations. The form-versus-JSON choice stays inside the siteverify implementation. Both encodings are still `secret` + `response` + `success`.

**Siteverify** — hCaptcha, classic reCAPTCHA, Turnstile, and `custom`. Move today's `postSiteverify` and `success` decode here. Behavior unchanged, including `remoteip` only when the client address is non-empty, and JSON only when `captchaProvider` is `custom` and `captchaCustomValidateBody` is `json`.

**Assessment** — `recaptcha-enterprise`, both key types. `POST` JSON to `https://recaptchaenterprise.googleapis.com/v1/projects/{project}/assessments`:

- `event.token` — the posted token
- `event.siteKey` — the configured site key
- `event.userIpAddress` — only when the client address is non-empty
- `event.expectedAction` — only when an action is configured

Send the API key as the `X-Goog-Api-Key` header, after one check that this endpoint accepts it. Do not put the key in the query string. Do not log the key. Use the `net/http` client the captcha client already holds and `captchaSiteverifyHTTPTimeoutSeconds`. No Google client library.

Pass, in order:

1. `tokenProperties.valid` is true.
2. When an action is configured, `tokenProperties.action` equals it.
3. When a minimum score is configured, `riskAnalysis.score` is at least that minimum.

A checkbox key with no minimum passes on `valid` alone. A missing or non-JSON body is an error outcome, not a reject.

## Widgets

`New` is the only switch on provider and key type. It pairs a widget with a verifier.

| | Checkbox | Score |
| --- | --- | --- |
| Script | `https://www.google.com/recaptcha/enterprise.js` | same URL with `?render={siteKey}` |
| Class | `g-recaptcha` | none |
| Token field | `g-recaptcha-response` | `g-recaptcha-response` |
| Boot | existing `data-callback` submits the form | `grecaptcha.enterprise.ready` then `execute(siteKey, {action})`, write the token into a hidden field, submit the form |
| Retry after reject | yes | no |

The boot script is fixed Go text for that key type. It reads the site key and the action from the page. It is not an operator-supplied string.

The stock `captcha.html` stays one page. Template data gains the boot script, the action, and whether to draw the checkbox. Existing placeholders `SiteKey`, `FrontendJS`, `FrontendKey`, and `ChallengeURL` stay. Operators who replace the template and want a score key must include the boot placeholder. Checkbox keeps working on a template that only has the current `g-recaptcha` div, as long as `FrontendJS` is the enterprise script.

## Config

Provider value: `recaptcha-enterprise`.

Required when this provider is selected, ignored otherwise. Same shape as the `captchaCustom*` fields, which are required only for `custom`.

| Knob | Role |
| --- | --- |
| `captchaEnterpriseKeyType` | `checkbox` or `score` |
| `captchaEnterpriseProjectId` | Google Cloud project id in the assessments URL |
| `captchaEnterpriseApiKey` | Cloud API key. File twin via `GetVariable`, same as the other secrets |

Optional or conditional:

| Knob | Checkbox | Score |
| --- | --- | --- |
| `captchaEnterpriseAction` | optional. Empty omits `data-action` and `expectedAction` | required |
| `captchaEnterpriseMinScore` | optional. Empty ignores `riskAnalysis.score` | required, and must be greater than zero |

`captchaSecretKey` is the siteverify shared secret. This provider does not use it. `ValidateParams` must not require it when the provider is `recaptcha-enterprise`. The gate secret stays required. The site key stays required.

These knobs are part of the captcha ownership payload (`pkg/captcha/session.go`), so a change reclaims the client.

`ValidateParams` may branch on the provider name to decide which fields are required. That branch already exists for `custom`. It does not run per request.

## Out of scope

- Service-account or OAuth auth for the assessments call.
- A third key type (policy-based challenge) as its own widget.
- Replacing classic `recaptcha` or routing a migrated classic key through assessments.
- A score threshold on hCaptcha, Turnstile, or classic reCAPTCHA v3.
- Changing the grace cookie, the gate HMAC, or captcha routing.

## Current (code)

- Classic `recaptcha` is `https://www.google.com/recaptcha/api.js`, class `g-recaptcha`, field `g-recaptcha-response`, validate `https://www.google.com/recaptcha/api/siteverify`: `pkg/captcha/captcha.go` (`infoProviders`).
- Built-in and custom verify POST `secret` + `response` (+ `remoteip` when the address is non-empty). Custom+`json` is that object as `application/json`; everyone else is `PostForm`. Pass is decoded `success` only: `pkg/captcha/captcha.go` (`siteverifyRequest`, `responseProvider`, `postSiteverify`, `Validate`).
- `Validate` is `(bool, error)`. Non-POST or empty token is `(false, nil)`. Transport or JSON `Decode` is `(false, err)`. Non-`application/json` Content-Type is `(false, nil)`, not an error: `pkg/captcha/captcha.go`.
- `ServeHTTP` logs `Validate` errors and still falls through. `valid` mints `crowdsec_captcha_gate`, sets the remediation header to `solved-captcha`, and `302`s to the request URL. Any other result always renders the challenge. There is no reject-versus-no-token split and no omitted boot script: `pkg/captcha/captcha.go`.
- Template data is only `SiteKey`, `FrontendJS`, `FrontendKey`, `ChallengeURL`. No boot script, action, or checkbox flag: `pkg/captcha/captcha.go`.
- Stock page loads `{{ .FrontendJS }}`, draws `<div class="{{ .FrontendKey }}" data-sitekey="{{ .SiteKey }}" data-callback="captchaCallback">`, and submits on that callback. No boot or action placeholder: `captcha.html`.
- Widget / Verifier types and `Pass(token, remoteIP)`: not found.
- `recaptcha-enterprise` constant, `enterprise.js`, assessments URL, `X-Goog-Api-Key`: not found.
- `captchaEnterpriseKeyType`, `captchaEnterpriseProjectId`, `captchaEnterpriseApiKey`, `captchaEnterpriseAction`, `captchaEnterpriseMinScore` (and File twins): not found.
- Provider allowlist is `""`, `hcaptcha`, `recaptcha`, `turnstile`, `custom`. Anything else fails `validateCaptcha`: `pkg/configuration/configuration.go`.
- When `captchaEnabled` and a provider is set, site key, secret key, gate secret, and template path are all required. Secret empty is `CaptchaSecretKey: cannot be empty when CaptchaProvider is set`: `pkg/configuration/configuration.go` (`validateCaptchaCredentials`, `validateEnabledCaptchaSettings`).
- Custom-only required fields already branch on provider name at `ValidateParams`: `pkg/configuration/configuration.go` (`validateCaptcha`).
- File-then-field secrets use `GetVariable(config, "Field")`, which reads `FieldFile` then `Field` by reflection. A missing `Field` / `FieldFile` pair panics: `pkg/configuration/configuration.go`.
- Ownership payload is provider, site, secret, gate, bind IP, template path, grace, siteverify timeout, and the `captchaCustom*` knobs. No enterprise knobs: `pkg/captcha/session.go` (`ownership`).
- Siteverify HTTP client is the one `newOwnerClient` stores, timeout `CaptchaSiteverifyHTTPTimeoutSeconds`: `pkg/captcha/session.go`.
- Gate cookie name `crowdsec_captcha_gate` and HMAC mint on pass: `pkg/captcha/gate.go`.
- README documents captcha validator tokens `hcaptcha`, `recaptcha`, `turnstile`, `custom`: `README.md`.
- Live config-validation spec SHALL resolve and reject empty `CaptchaSecretKey` whenever `captchaEnabled` is true: `openspec/specs/core_plugin_middleware_config-validation/spec.md`.
- Live siteverify spec freezes built-ins as hcaptcha / recaptcha / turnstile plus custom `secret`+`response`+`success`: `openspec/specs/core_plugin_middleware_captcha-siteverify/spec.md`.
- Existing recaptcha research is classic `/siteverify` only: `knowledge/research/index_ext_recaptcha.md`. Assessments research: not found.

## Out of scope

- Service-account or OAuth auth for the assessments call.
- A third key type (policy-based challenge) as its own widget.
- Replacing classic `recaptcha` or routing a migrated classic key through assessments.
- A score threshold on hCaptcha, Turnstile, or classic reCAPTCHA v3.
- Changing the grace cookie, the gate HMAC, or captcha routing.
- Changing `IsCaptchaFormPost` / form peeking for origin-forwarded POSTs (`pkg/captcha/captcha.go`). Score and checkbox both keep the field name `g-recaptcha-response`.
- Changing hCaptcha, Turnstile, or `custom` request encoding or the `success` pass bit (`pkg/captcha/captcha.go`).
- Changing AppSec or LAPI legs, or adding a Google client library to `go.mod`.
- A second bundled template file; the stock page stays `captcha.html`.

## Unknowns

- Whether `POST https://recaptchaenterprise.googleapis.com/v1/projects/{project}/assessments` accepts `X-Goog-Api-Key` (the spec requires one check) versus only `?key=`. Explore / `skill:opd-research:Investigate then write`.
- Assessment JSON field names, score range and type, and HTTP status on invalid token versus invalid API key.
- Whether enterprise checkbox still uses `g-recaptcha`, `g-recaptcha-response`, and `data-callback` on `enterprise.js`.
- Exact score-key boot (`grecaptcha.enterprise.ready` / `execute`) and whether a refused score token can be executed again without omitting the script.
- How `captchaEnterpriseMinScore` is typed in Traefik YAML (`float64` vs string) and what “greater than zero” means at the boundary.
- How `Validate` exposes no-token vs reject vs error without `ServeHTTP` branching on provider name (return type vs extra result).
- Action string equality (case, empty vs omitted `expectedAction`).
- Operator blast radius of dropping the live SHALL that always requires `CaptchaSecretKey`.

## Tensions

- The spec says Error is “the body was not decodable JSON. Same classification as siteverify today: `(false, err)`”, and also that a missing or non-JSON assessment body is an error, not a reject. Today a non-`application/json` siteverify Content-Type is `(false, nil)` (`pkg/captcha/captcha.go`). “Same as siteverify” and “missing body is error” disagree; explore must pick one for assessment.
- The spec heading says `Validate` returns three outcomes, then the table lists four (No token, Pass, Reject, Error). `Verifier.Pass` stays `(bool, error)`. Not a second product ask; explore names the Go result.
- Live spec `openspec/specs/core_plugin_middleware_config-validation/spec.md` SHALL require `CaptchaSecretKey` when `captchaEnabled` is true. The ticket says that key is unused and must not be required for `recaptcha-enterprise`. Explore treats that SHALL as the freeze this change replaces.
- Live spec `openspec/specs/core_plugin_middleware_captcha-siteverify/spec.md` freezes built-in verify as siteverify `secret`+`response`+`success`. The ticket adds a second verifier. Same kind of stale-SHALL row, not a requester disagreement.
