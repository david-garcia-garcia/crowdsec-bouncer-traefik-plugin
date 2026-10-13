## Context

See proposal.md — Why. Today `pkg/captcha/captcha.go` hardcodes classic `api.js` / `g-recaptcha` / `siteverify` on `infoProviders`. `Validate` is `(bool, error)`: non-POST or empty token is `(false, nil)`, same as provider `success:false`. `ServeHTTP` always re-renders the challenge on any non-pass. `validateCaptchaCredentials` always requires `CaptchaSecretKey`. Ownership in `pkg/captcha/session.go` has no enterprise knobs. Caller design: `docs/recaptcha-enterprise.md`. Research: `knowledge/research/ext_recaptcha_enterprise_assessments/`, `knowledge/research/ext_recaptcha_enterprise_widget/`. Identity owner is `GetRemoteIP` / `clientRequest.remoteIP` already passed into `ServeHTTP` / `Validate`.

## Goals / Non-Goals

**Goals:**
- Split construction into Widget + Verifier so the request path never names a provider.
- Keep siteverify as today's `secret`+`response`+`success` implementation.
- Add an assessments verifier that uses the existing captcha `http.Client` and timeout.
- Distinguish None from Reject so a score refusal can omit the boot script.
- Validate enterprise knobs at `ValidateParams` the same way `captchaCustom*` is custom-only.

**Non-Goals:**
- Service-account or OAuth for assessments.
- A third (policy-based) widget.
- Replacing classic `recaptcha` or sending a migrated classic key to assessments.
- Score on hCaptcha, Turnstile, or classic v3.
- Changing the gate cookie, captcha routing, or `IsCaptchaFormPost`.
- A Google client library or a second bundled template.

## Decisions

1. `Validate` result is `(Outcome, error)` with `None`, `Pass`, `Reject`. Error is the error return. `Verifier.Pass` stays `(bool, error)`. Alternative: extra result enum beside `(bool, error)` — rejected; one return already has to change and ServeHTTP is the only production caller.
2. Assessment classify: non-2xx, missing/non-JSON body, or a Google error envelope without `tokenProperties` → Error. Successful Assessment with `valid == false` → Reject. Alternative: treat a Google error envelope as Reject — rejected; that is not a token refusal.
3. Auth is `X-Goog-Api-Key` only. Cloud system parameters list that header as the HTTP form of `key`. The reCAPTCHA sample shows `?key=` only. Query string and OAuth are out of scope. If the endpoint later rejects the header, stop.
4. Action compare is case-insensitive. Official action names are not case-sensitive. Empty after trim omits `event.expectedAction` and skips the check (checkbox). Score requires a non-empty action at `ValidateParams`.
5. `captchaEnterpriseMinScore` is a `string` on Config (this plugin has no `float64` knobs; Traefik `WeaklyTypedInput` will coerce a YAML number). Parse at `ValidateParams`. Empty = omit (checkbox). Score requires parsed value `> 0` and `<= 1`.
6. Do not grow `Client.New`'s positional list. Pass enterprise knobs as a named construction value `New` already switches on. Alternative: more positional strings — rejected; the list is already long.
7. Template map stays `map[string]string`. Placeholders: `BootScript`, `Action`, `DrawCheckbox` (non-empty when the checkbox div should render). Alternative: typed template data — rejected; the stock page and operator replacements already take a string map.
8. Siteverify Content-Type miss stays `(false, nil)` inside Pass. “Same as siteverify `(false, err)`” is JSON `Decode` / transport only. Assessment missing/non-JSON is Error.
9. Rejected: route enterprise through `custom` (body and `success` cannot express assessments). Rejected: replace classic `recaptcha`.

## Risks / Trade-offs

- [Google's reCAPTCHA sample only shows `?key=`] → send the Cloud-wide header; do not log the key; stop if a later assessments note shows the header rejected.
- [`Validate` signature change] → one production caller (`ServeHTTP`) and the `zzz_validate_body` tests; update those, not bounce routing.
- [Operator templates that omit `BootScript`] → checkbox still works when `FrontendJS` is `enterprise.js`; score needs the new placeholder (documented).
- [Dropping the always-required secret SHALL] → skip the empty-secret reject only for `recaptcha-enterprise`. Other providers unchanged.
- [Score omit-boot is a product choice, not a Google requirement] → official docs say call `execute` on each interaction; omitting boot after Reject prevents an auto-loop on the same page.

## Migration Plan

Classic `recaptcha` / hCaptcha / Turnstile / `custom` YAML is unchanged. Operators who want Cloud keys set `captchaProvider: recaptcha-enterprise` and the enterprise knobs. Roll back by reverting the provider token; leftover enterprise keys are ignored.

## Open Questions

None — ticket decisions stand on `explore.md`.
