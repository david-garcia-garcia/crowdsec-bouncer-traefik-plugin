# Explore
IssueKey: 2026-09-06-upstream-380-trycap-captcha

## Concepts

Captcha remediation is a Bouncer concern, not LAPI or AppSec reclaim. `pkg/bouncer` constructs `pkg/captcha.Client` in `New` and calls `Check` / `ServeHTTP` when the CrowdSec decision (or a failure action) is captcha. Client address is already `clientRequest.remoteIP` from `pkg/ip.GetRemoteIP`; captcha only uses that string as a cache key suffix (`remoteIP+"_captcha"`). Do not parse `RemoteAddr` again in `pkg/captcha`.

Today the Captcha Client has one verify shape: `http.Client.PostForm` with urlencoded `secret` + `response`, reading `r.FormValue(infoProvider.response)`. Built-ins (`hcaptcha`, `recaptcha`, `turnstile`) fill `infoProvider` from a package map (fixed JS URL, CSS class, form field, validate URL). `custom` copies `CaptchaCustom*` into the same struct. The default `captcha.html` is one template for all of them: `<script src="{{ .FrontendJS }}">` plus `<div class="{{ .FrontendKey }}" data-sitekey="{{ .SiteKey }}" data-callback="captchaCallback">` that auto-POSTs the form.

Cap Standalone (trycap.dev) does not fit that shape:

```
Browser                         Traefik plugin                      Cap instance
   |                                  |                                   |
   |  GET (captcha decision)          |                                   |
   |<----- captcha.html --------------|                                   |
   |  cap-widget + type=module JS     |                                   |
   |  data-cap-api-endpoint=          |                                   |
   |  https://<instance>/<site_key>/  |                                   |
   |----------------------------------+---------------------------------->|
   |  solve → hidden cap-token        |                                   |
   |  POST form to same URL --------->|                                   |
   |                                  |  POST JSON {secret,response}      |
   |                                  |  Content-Type: application/json   |
   |                                  |  https://<instance>/<site_key>/   |
   |                                  |  siteverify ---------------------->|
   |                                  |<----- {success:true} --------------|
   |<----- 302 + cache set -----------|                                   |
```

Official client: web component `<cap-widget data-cap-api-endpoint="https://<instance>/<site_key>/">`. Widget JS is npm `cap-widget` (jsDelivr), `type="module"`, not a class-based recaptcha-style div. Official server: POST JSON `{"secret","response"}` to `/<site_key>/siteverify`. Success body `{ "success": true }` (same JSON field this plugin already decodes). Form field default `cap-token`. Marketing text says siteverify is reCAPTCHA-compatible; the documented curl/fetch is JSON, not `application/x-www-form-urlencoded`. This product follows the documented curl.

`custom` cannot be the TryCap operator path: it still `PostForm`s, and the default template has no `data-cap-api-endpoint` slot. Reusing `CaptchaCustomValidateURL` as the instance URL would make operators paste a full siteverify URL into a field documented as “validate URL”, then still fail on Content-Type.

## Decisions

- First-class provider `trycap` next to `hcaptcha` / `recaptcha` / `turnstile` / `custom`. Not a `custom` profile.
- New operator key `captchaTrycapInstanceUrl` (public origin of the Cap Standalone instance, no site-key path). Derive widget endpoint `{instance}/{siteKey}/` and verify URL `{instance}/{siteKey}/siteverify` in `New`. Reuse existing `captchaSiteKey` / `captchaSecretKey`. Do not add CaptchaCustom* requirements for this provider.
- Default widget JS: jsDelivr `cap-widget` URL in `infoProviders` (same pattern as the three SaaS JS URLs). Operators who must self-host the script customize `captchaFilePath`.
- Default `captcha.html` stays one file. Template data grows a Cap widget slot (`CapApiEndpoint` or empty). When set, render `<cap-widget>` and load FrontendJS as `type="module"`; when empty, keep the class+callback div. Auto-submit on Cap `solve` to match current UX. Do not ship a required second template file.
- `Validate` for `trycap` POSTs JSON (`application/json`) and reads `cap-token`. Other providers keep `PostForm`. Do not change `custom` to JSON (upstream #318 stays a follow-up).
- Extend `infoProvider` (verify encoding + constructed URLs). Do not add a second captcha client type.
- Proof: `pkg/captcha` unit tests with `httptest` (JSON body, URL join, missing token, success JSON). No Cap Docker in CI e2e this change (operator-owned instance; out of scope to ship the container). README + `examples/trycap-captcha` labels/template notes, not a live Cap stack in mock e2e.
- Captcha HTTP client and template stay on Bouncer (`core_plugin_middleware`). No reclaim / `sync.Once` / package global.

## Open questions

- Q: What is the official product name for the provider enum and docs — TryCap, Cap, or Cap Standalone?
  Decision: assumed — enum and json key use `trycap` (ticket URL trycap.dev, distinct from `custom`); operator-facing README says Cap Standalone (trycap.dev) and the key `captchaTrycapInstanceUrl`.
  By: explore

- Q: Where does the widget JavaScript load from — the instance or a CDN?
  Decision: assumed — official widget docs load `https://cdn.jsdelivr.net/npm/cap-widget` as `type="module"`; pin a version in the built-in JS URL like the SaaS providers pin theirs. Instance URL is only the API endpoint, not the script host.
  By: explore

- Q: Does instance URL belong in a dedicated config key or reuse CaptchaCustomValidateURL?
  Decision: assumed — dedicated `captchaTrycapInstanceUrl`. Custom validate URL is a full siteverify URL for urlencoded providers; mixing them would mislead operators and still use PostForm.
  By: explore

- Q: Can default captcha.html serve all providers, or does TryCap need a separate template?
  Decision: assumed — one default template with a conditional Cap widget branch; custom `captchaFilePath` remains the escape hatch.
  By: explore

- Q: Does Cap siteverify accept recaptcha-style form-urlencoded, so PostForm would work?
  Decision: assumed — no; documented contract is JSON `Content-Type: application/json`. Marketing “reCAPTCHA compatible” is not a second Content-Type. Do not send PostForm for `trycap`.
  By: explore

- Q: Who already owns the client address used as the captcha grace cache key?
  Decision: resolved — `pkg/ip.GetRemoteIP` via Bouncer `clientRequest.remoteIP`. Captcha Check/Set reuse that string. Do not parse RemoteAddr or XFF in pkg/captcha.
  By: explore

- Q: Should this change also make `custom` POST JSON (upstream #318 CapJS)?
  Decision: assumed — no. Out of scope on requirement.md. Note as follow-up on issues.md.
  By: explore

- Q: Must CI e2e run a live `tiago2/cap` container?
  Decision: assumed — no. Unit tests prove verify; example docs show operator wiring. Shipping/deploying Cap Standalone is out of scope.
  By: explore
