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

`Validate` returns `(Outcome, error)` with `None`, `Pass`, and `Reject`. Error is the error return. `Verifier.Pass` stays `(bool, error)`.

| Outcome | When |
| --- | --- |
| None | The request is not a POST, or the token field is empty. |
| Pass | `verifier.Pass` returns true. |
| Reject | A token was posted and `verifier.Pass` returns false with no error. |
| Error | Transport failed, or the body was not decodable JSON. Siteverify still returns `(false, err)` from `Pass` for transport and JSON `Decode` only. A siteverify Content-Type miss stays Pass-false with no error. Assessment missing or non-JSON body is Error. |

`ServeHTTP`:

- Error or None: render the challenge. The boot script runs.
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
- `event.userIpAddress` — only when the client address is non-empty. That address is `GetRemoteIP` / `clientRequest.remoteIP` already passed into `Validate` / `Pass`. Do not parse forwarded headers in captcha.
- `event.expectedAction` — only when an action is configured (non-empty after trim)

Send the API key as the `X-Goog-Api-Key` header. Do not put the key in the query string. Do not log the key. Use the `net/http` client the captcha client already holds and `captchaSiteverifyHTTPTimeoutSeconds`. No Google client library.

Pass, in order:

1. `tokenProperties.valid` is true.
2. When an action is configured, `tokenProperties.action` equals it case-insensitively.
3. When a minimum score is configured, `riskAnalysis.score` is at least that minimum.

A checkbox key with no minimum passes on `valid` alone. A missing or non-JSON assessment body, a non-2xx response, or a Google error envelope without `tokenProperties` is an error outcome, not a reject. A successful Assessment with `valid` false is Reject.

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

The stock `captcha.html` stays one page. Template data keeps `SiteKey`, `FrontendJS`, `FrontendKey`, and `ChallengeURL`, and gains `BootScript`, `Action`, and `DrawCheckbox`. The map stays `map[string]string`. `DrawCheckbox` is non-empty when the checkbox div should render. Operators who replace the template and want a score key must include the boot placeholder. Checkbox keeps working on a template that only has the current `g-recaptcha` div, as long as `FrontendJS` is the enterprise script.

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
| `captchaEnterpriseMinScore` | optional. Empty ignores `riskAnalysis.score`. String on Config; parse at `ValidateParams`. | required. Parsed `float64` greater than zero and at most 1. Zero, negative, 1.1, and non-numeric fail. |

`captchaSecretKey` is the siteverify shared secret. This provider does not use it. `ValidateParams` must not require it when the provider is `recaptcha-enterprise`. The gate secret stays required. The site key stays required.

These knobs are part of the captcha ownership payload (`pkg/captcha/session.go`), so a change reclaims the client.

`ValidateParams` may branch on the provider name to decide which fields are required. That branch already exists for `custom`. It does not run per request.

## Out of scope

- Service-account or OAuth auth for the assessments call.
- A third key type (policy-based challenge) as its own widget.
- Replacing classic `recaptcha` or routing a migrated classic key through assessments.
- A score threshold on hCaptcha, Turnstile, or classic reCAPTCHA v3.
- Changing the grace cookie, the gate HMAC, or captcha routing.
