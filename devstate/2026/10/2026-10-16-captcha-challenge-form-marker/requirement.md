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

- After a captcha decision, a valid gate cookie plus a POST that IsCaptchaFormPost treats as a captcha form is answered with WriteSolvedRedirect (302 to the same URL) and is not forwarded: pkg/bouncer/bouncer.go (handleCaptchaKindServeHTTP).
- IsCaptchaFormPost is true only for POST whose provider TokenField is non-empty in a body of at most 64KiB (or already-parsed PostForm): pkg/captcha/captcha.go.
- Provider token field names: g-recaptcha-response (pkg/captcha/provider_siteverify.go classic recaptcha; pkg/captcha/provider_enterprise.go both key types), h-captcha-response and cf-turnstile-response (pkg/captcha/provider_siteverify.go), u-captcha-response (pkg/captcha/provider_eucaptcha.go), custom uses the configured response field (pairCustom in pkg/captcha/provider_siteverify.go).
- First solve: Validate still reads that same TokenField, then ServeHTTP mints crowdsec_captcha_gate and 302s: pkg/captcha/captcha.go.
- Gate cookie check is Client.Check: pkg/captcha/captcha.go. Field crowdsec_captcha_challenge is not found.
- Stock challenge form has no CrowdSec-owned marker; checkbox omits a hidden provider input (vendor injects it); score path hardcodes g-recaptcha-response: captcha.html.
- Example templates: xamples/captcha/captcha.html, xamples/custom-captcha/captcha.html — POST form, no marker.
- Test pages: 	ests/e2e/real/config/captcha-dummy.html, 	ests/e2e/mock/scenarios/captcha/captcha.html, 	ests/e2e/mock/scenarios/captcha-ban-origins/captcha.html — dummy provider field, no marker.
- Live contract ratifies provider-field detection for the Check-true redirect: openspec/specs/core_plugin_middleware_captcha-routing/spec.md.
- Tests that encode that signal: pkg/captcha/zzz_routing_test.go (Test_IsCaptchaFormPost*), pkg/bouncer/zzz_captcha_routing_test.go (TestHandleRemediationServeHTTP_solvedFormPostRedirects, TestHandleRemediationServeHTTP_ordinaryPostAfterSolveReachesOrigin).

## Out of scope

- Changing the URL of the first unsolved POST redirect (the visitor solves on that POST URL and the browser returns with a GET). Named in the spec; not taken.
- A new Traefik setting for the marker name or value.
- Changing the gate cookie name, HMAC, bind-IP, or grace.
- Renaming vendor token fields (g-recaptcha-response and siblings) on first-solve Validate.
- Changing first-solve provider-token verification.

## Unknowns

- Whether Check-true marker detection reuses IsCaptchaFormPost's 64KiB peek, multipart, and already-parsed PostForm rules, or a sibling reader.
- Blast radius of operator-replaced templates that omit the new field (second submit becomes origin traffic).
- Whether any application already POSTs crowdsec_captcha_challenge=v1.
- Browser 302-after-POST GET conversion cited in the spec is not re-measured here.

## Tensions

- Live spec core_plugin_middleware_captcha-routing requires the Check-true redirect when the provider response field is non-empty; the ticket requires that branch to read crowdsec_captcha_challenge=v1 only. Propose must delta that spec.
- Stock captcha.html checkbox branch has no hidden provider input; the ticket's marker is plugin-owned and must appear on both checkbox and score branches.
- Replaced templates that omit the marker keep first-solve (Validate still uses the vendor field) but lose the duplicate-tab redirect. That is the ticket's stated operator migration, not a silent extra ask.
