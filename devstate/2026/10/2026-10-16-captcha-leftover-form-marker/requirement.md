# Captcha challenge form marker

## Problem

After a visitor has solved the CrowdSec captcha, a later POST from the application can be treated as another CrowdSec challenge and never reach the application.

The visitor has a valid gate cookie. They submit an ordinary application form. The plugin answers `302 Found` to that same URL. Browsers follow a 302 after a POST with a GET and drop the body. A route that accepts only POST then renders its own not-found page. The address bar stays on the POST URL, so a refresh repeats the GET.

The captcha provider being configured is not enough to cause this. The redirect runs only when a captcha decision matches the visitor, so the request is still on the captcha path, and the gate cookie is already valid.

## Why the signal is wrong

On that path the plugin asks one question: does this POST contain the provider's response field?

| Provider | Field the plugin treats as "our form" |
| --- | --- |
| reCAPTCHA, classic and Enterprise | `g-recaptcha-response` |
| hCaptcha | `h-captcha-response` |
| Turnstile | `cf-turnstile-response` |
| EU CAPTCHA | `eu-captcha-response` |
| custom | the configured response field |

Those names mean "a vendor token is present." They do not mean "this POST is the CrowdSec challenge."

Vendor widgets choose the names. An application that embeds the same vendor widget posts the same field, next to its own fields (credentials, form key, and so on). The plugin cannot tell that POST from a second submit of the CrowdSec challenge, so it redirects it.

The check exists for a real case. The gate cookie is shared across tabs. One tab can solve the challenge while another tab still has the challenge form open. Submitting that leftover form would POST only the vendor token to the application URL. The redirect keeps that POST off the application. The mistake is using the vendor's field as proof that the POST is ours.

Renaming `g-recaptcha-response` inside the plugin does not fix it. On a checkbox challenge the vendor script creates that field itself. The application and the plugin would still share it.

## Proposed solution

Put a hidden field on the CrowdSec challenge form. When the gate cookie is not valid, request handling stays unchanged: the captcha decision serves the challenge, and a regular POST carrying the provider token can solve it. Only after the visitor has cleared the gate does the plugin require this marker to identify a leftover CrowdSec challenge POST.

```html
<input type="hidden" name="crowdsec_captcha_challenge" value="v1">
```

After a captcha decision matches:

```text
Valid gate cookie?
├─ no
│  └─ unchanged: read the provider token, verify it, set the cookie, redirect
└─ yes
   ├─ POST contains crowdsec_captcha_challenge=v1
   │  └─ leftover CrowdSec challenge: 302 to the same URL, do not forward
   └─ anything else
      └─ forward the request unchanged, body included
```

On the valid-gate branch, duplicate-form detection reads that marker only. It does not look at `g-recaptcha-response` or any other provider field. A POST that carries a vendor token and does not carry the marker is application traffic. Before the gate is cleared, provider-token validation remains unchanged.

The marker grants nothing. A client that forges it only forces its own POST to be redirected. Passage still depends on the gate cookie. The provider token field stays as the vendor defines it, and the first solve still reads it for verification.

## What stays the same

- First solve: verify the provider token, set the gate cookie, redirect.
- A solved visitor's ordinary GET and POST reach the application.
- A second submit of our challenge form, cookie already set, is still redirected and is not sent to the application.
- No new Traefik setting. No change to the gate cookie.

## Templates

The stock challenge page, the examples, and the test pages gain the hidden field.

A replaced template that omits the field still solves on the first submit. A second submit of that template is forwarded, because the plugin no longer guesses from the vendor field. Operators who rely on the duplicate-tab redirect add the same hidden input to their template.

## Out of scope

A captcha decision can replace an application POST before any gate cookie exists. The visitor then solves the challenge on that POST URL, and the browser returns with a GET. This change does not choose a different URL for that first redirect. It only stops a solved visitor's own form POST from being mistaken for the challenge.

## Current (code)

- A captcha decision reaches `handleRemediationServeHTTP` then `handleCaptchaKindServeHTTP` (`pkg/bouncer/bouncer.go`).
- Valid gate cookie is `Client.Check` reading `crowdsec_captcha_gate` (`pkg/captcha/captcha.go`, `pkg/captcha/gate.go`).
- After `Check` is true, a POST that `IsCaptchaFormPost` accepts is `WriteSolvedRedirect`: `302 Found` to the same URL, origin not called (`pkg/bouncer/bouncer.go`, `pkg/captcha/captcha.go`). Covered by `pkg/bouncer/zzz_captcha_routing_test.go`.
- `IsCaptchaFormPost` is true when the POST has a non-empty `widget.TokenField` (`pkg/captcha/captcha.go`). It peeks at most `captchaFormMaxBytes` (`64KiB`) in `pkg/captcha/form.go`; a larger body is not treated as a captcha form.
- Token field names: `g-recaptcha-response` (`pkg/captcha/provider_siteverify.go`, `pkg/captcha/provider_enterprise.go`), `h-captcha-response` (`pkg/captcha/provider_siteverify.go`), `cf-turnstile-response` (`pkg/captcha/provider_siteverify.go`), `eu-captcha-response` (`pkg/captcha/provider_eucaptcha.go`), custom `CaptchaCustomResponse` (`pkg/configuration/configuration.go` via `pairCustom` in `pkg/captcha/provider_siteverify.go`).
- First solve still uses `Validate` → `readFieldFromRequest` on `TokenField`, then mints the gate cookie and 302s to the same URL (`pkg/captcha/captcha.go`).
- Hidden `crowdsec_captcha_challenge`: `not found` in `captcha.html`, `examples/captcha/captcha.html`, `examples/custom-captcha/captcha.html`, `tests/e2e/real/config/captcha-dummy.html`, `tests/e2e/mock/scenarios/captcha/captcha.html`, `tests/e2e/mock/scenarios/captcha-ban-origins/captcha.html`.
- No Traefik setting for that marker: `not found` on `Config` in `pkg/configuration/configuration.go`. Gate cookie name and payload stay in `pkg/captcha/gate.go`.

## Out of scope

- New Traefik / plugin keys for the marker.
- Changing `crowdsec_captcha_gate` name, HMAC, or bind-IP rules (`pkg/captcha/gate.go`).
- Renaming vendor token fields (`g-recaptcha-response` and the rest).
- A different URL for the first unsolved captcha 302 (already in the spec Out of scope above).

## Unknowns

- Whether operator-replaced templates in the field omit the new hidden input, and how many rely on the current TokenField leftover redirect.
- Whether vendor widgets inject their token field into ordinary application POSTs in every provider mode (checkbox vs score vs custom). Explore owns vendor facts.
- Whether leftover-form detection after this change should keep the `64KiB` peek cap in `pkg/captcha/form.go`.
- Blast radius of forwarding a second submit of a replaced template that still posts only the vendor token.

## Tensions

- Spec leftover detection is “POST contains `crowdsec_captcha_challenge=v1`” with no size cap. Current leftover detection skips bodies over `captchaFormMaxBytes` even when `TokenField` is present (`pkg/captcha/form.go`, `pkg/bouncer/zzz_captcha_routing_test.go`).
- Spec says a replaced template that omits the marker forwards a second submit. Current code redirects that submit whenever `TokenField` is present (`pkg/bouncer/bouncer.go`). That is the gap, not a second product ask.
