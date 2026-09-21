# CapJS custom captcha JSON siteverify

Cap Standalone / CapJS wants:
  POST https://<instance>/<site_key>/siteverify
  Content-Type: application/json
  {"secret":"<key>","response":"<cap-token>"}
  reply {"success":true}
See https://trycap.dev/guide/standalone/

Current dest: pkg/captcha/captcha.go Validate always PostForm urlencoded secret+response. bouncerCaptchaCustomResponse already names the browser field (set cap-token). The second hop encoding is not configurable.

Desired:
- New optional knob bouncerCaptchaCustomValidateBody / BouncerCaptchaCustomValidateBody: "" or "form" = PostForm (today); "json" = POST application/json object with secret and response.
- Knob is custom-only. Built-in hcaptcha/recaptcha/turnstile always PostForm. Reject unknown values and reject json when provider is not custom.
- Default omit keeps Wicketkeeper examples working (examples/custom-captcha).
- Do not add bouncerCaptchaProvider: trycap, captchaTrycapInstanceUrl, or a <cap-widget> template branch. Extra verify fields/headers out of scope.
- README: document the knob and a CapJS custom example (validate URL + cap-token + json body). Do not retarget Wicketkeeper official JSON.
- If dest or sibling 2026-09-18-captcha-verify-template-ux already threads remoteIP into Validate, include remoteip on BOTH encodings when non-empty. Do not invent remoteip if Validate(r) still has no IP on the dest you branched from — rebase/sync origin/master during implement and pick up leftover if it merged.
- Keep gate cookie on success (mintGateValue/setGateCookie/302). Keep #94 Content-Type rule for the response. Do not change cache.Client.Set.

Tests:
- custom + json: httptest siteverify sees Content-Type application/json and JSON secret/response (and remoteip if Validate has it).
- custom + form/omit: still urlencoded PostForm.
- built-in provider ignores a json knob or validation rejects it — pick one in explore and test it.
- unknown body value fails ValidateParams.
- success still 302 + Set-Cookie.

Bound: do not implement leftovers (template required, 200-on-retryable) except absorb remoteip if already on dest. Do not implement split HTTP timeouts or backendbackoff. Do not touch LAPI/AppSec/Range/module path.

Upstream context only (do not open upstream PRs): maxlerebourg/crowdsec-bouncer-traefik-plugin#318 — CapJS Standalone siteverify is JSON, plugin always PostForm.

Do NOT reuse closed PR #52 or branch 2026-09-06-upstream-318-capjs-custom-captcha. Owner declined that PR as stale (cache-grace Validate). Do not reuse closed unmerged PR #40 trycap provider.
