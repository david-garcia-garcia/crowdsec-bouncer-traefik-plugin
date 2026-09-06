## Context

See proposal.md — Why. `pkg/captcha.Client` has one `infoProvider` (js, key, response, validate) and `Validate` always `PostForm`s. Default `captcha.html` is a class widget with `data-callback`. Cap Standalone needs JSON siteverify, form field `cap-token`, `<cap-widget data-cap-api-endpoint>`, and `type="module"` script. Captcha stays on Bouncer (`core_plugin_captcha`). Client IP stays `clientRequest.remoteIP`.

## Goals / Non-Goals

**Goals:**
- Built-in `trycap` with one new origin key and derived URLs.
- JSON verify only on that provider; template branch in the default file.
- Unit tests that assert Content-Type and path.

**Non-Goals:**
- JSON `custom` (upstream #318).
- Shipping `tiago2/cap` in CI e2e.
- Changing LAPI/AppSec reclaim or a second client-IP parse.

## Decisions

1. **Provider string `trycap`.** Matches trycap.dev and stays distinct from `custom`. Alternative: `cap` — rejected; too easy to confuse with CrowdSec captcha remediation.

2. **Dedicated `captchaTrycapInstanceUrl`.** Operator pastes the public origin. `New` joins `{instance}/{siteKey}/` and `{instance}/{siteKey}/siteverify` (trim trailing slashes). Alternative: reuse `CaptchaCustomValidateURL` — rejected; that field is a full urlencoded verify URL.

3. **Extend `infoProvider` with JSON-body and API-endpoint slots.** `Validate` branches on the JSON flag; `ServeHTTP` passes `CapApiEndpoint` into the template. Alternative: a second client type — rejected; one job is still “captcha provider coordinates”.

4. **Built-in JS URL is pinned jsDelivr `cap-widget` (module).** Same pattern as SaaS JS URLs. Alternative: load widget JS from the instance — rejected; official widget docs use CDN/npm `cap-widget`; the instance is the API endpoint.

5. **One default `captcha.html` with a `CapApiEndpoint` conditional.** Auto-submit on Cap `solve` to match today’s callback UX. Alternative: a required second template file — rejected; operators who customize already have `captchaFilePath`.

6. **Proof is `pkg/captcha` httptest**, not a Cap Docker scenario. Alternative: mock e2e with `tiago2/cap` — rejected; out of scope to ship the container.

## Risks / Trade-offs

- [Operators with a custom captcha.html miss the Cap branch] → README documents the new template keys; default file covers stock installs.
- [jsDelivr blocked in some regions] → documented; self-host the script via `captchaFilePath`.
- [Marketing “reCAPTCHA compatible” vs JSON Content-Type] → send JSON only; do not PostForm for `trycap`.

## Migration Plan

Non-breaking. Operators set `captchaProvider: trycap`, `captchaTrycapInstanceUrl`, site and secret keys. Rollback: previous tag ignores the new key.
