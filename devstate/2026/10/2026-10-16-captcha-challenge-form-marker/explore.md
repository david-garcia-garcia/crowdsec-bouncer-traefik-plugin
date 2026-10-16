# Explore

## Concepts

Units this change would touch:

- `handleCaptchaKindServeHTTP` (`pkg/bouncer/bouncer.go`) — captcha-kind router after custom-resource passthrough: Check-true leftover-form 302, else origin, else first-solve `ServeHTTP`.
- `Client.IsCaptchaFormPost` (`pkg/captcha/captcha.go`) plus peek helpers (`pkg/captcha/form.go`: `peekCaptchaFormBody`, `formFieldValue`, `captchaFormMaxBytes` 64KiB) — body-safe leftover-form detection on a request that may still be forwarded.
- `Client.Validate` / `readFieldFromRequest` (`pkg/captcha/captcha.go`, `pkg/captcha/form.go`) — first-solve provider token; must stay a separate reader.
- `Client.Check` / gate cookie (`pkg/captcha/captcha.go`, `core_plugin_middleware_captcha-gate`) — already owns past-captcha; client address stays on inbound `clientrequest.Request`.
- `Client.WriteSolvedRedirect` — Check-true 302 to `req.URL.String()`, no remint, no siteverify.
- Challenge HTML: stock `captcha.html` (checkbox omits a hidden provider input; score hardcodes `g-recaptcha-response`), `examples/captcha/captcha.html`, `examples/custom-captcha/captcha.html`, `tests/e2e/real/config/captcha-dummy.html`, `tests/e2e/mock/scenarios/captcha/captcha.html`, `tests/e2e/mock/scenarios/captcha-ban-origins/captcha.html`.
- Live contract `openspec/specs/core_plugin_middleware_captcha-routing/spec.md` and usage `knowledge/devdocs/core_plugin_middleware_captcha-routing.md` (Language **Solved-form POST** is currently TokenField).

How they connect:

```
handleCaptchaKindServeHTTP
  custom-resource path?  --> return false (origin / AppSec)
  Check(req)?            [gate cookie; address already on inbound request]
    yes + leftover-form  --> WriteSolvedRedirect (302 same URL)
    yes + anything else  --> return false (forward, body included)
    no                   --> ServeHTTP: Validate(TokenField) then mint cookie / challenge
```

Today leftover-form is `IsCaptchaFormPost` = POST + non-empty `widget.TokenField` in a <=64KiB urlencoded/multipart (or already-parsed `PostForm`) body. After this change that Check-true test reads `crowdsec_captcha_challenge=v1` only. Check-false still verifies TokenField.

Call sites that matter: **1** production caller of `IsCaptchaFormPost` (`handleCaptchaKindServeHTTP`). Roots searched: `pkg/bouncer`, `pkg/captcha`, `tests/`, `examples/`, `captcha.html`, `knowledge/devdocs`, `openspec/specs`. Tests that encode the current TokenField signal: `pkg/captcha/zzz_routing_test.go` (`Test_IsCaptchaFormPost*`), `pkg/bouncer/zzz_captcha_routing_test.go` (`TestHandleRemediationServeHTTP_solvedFormPostRedirects`, `ordinaryPostAfterSolveReachesOrigin`, `overMaxPostAfterSolveReachesOriginIntact`).

Reproduce: **reproduced** as current code, not as a failing test. `go test ./pkg/captcha/ ./pkg/bouncer/ -count=1 -run "Test_IsCaptchaFormPost$|Test_IsCaptchaFormPost_|TestHandleRemediationServeHTTP_solvedFormPostRedirects|TestHandleRemediationServeHTTP_ordinaryPostAfterSolveReachesOrigin"` passed. Check-true POST with `dummy-captcha-response` is 302; POST `comment=hi` after solve reaches origin. Application POST that also carries a vendor widget field was not exercised (no in-tree origin form with `g-recaptcha-response`). Browser 302-after-POST GET conversion: **not reproduced** (requirement: not re-measured here).

Outside facts: vendor widgets inject TokenField names (`ext_recaptcha_enterprise_widget`, `ext_eucaptcha_widget`; in-tree `TokenField` in `pkg/captcha/provider_*.go`). HTTP 302 POST→GET: in-tree spec citation only. No new research folder.

## Decisions

- Chosen: Check-true leftover-form detection reads hardcoded `crowdsec_captcha_challenge=v1` only; first-solve Validate still reads TokenField; no Traefik setting; no gate-cookie change.
- Chosen: reuse `IsCaptchaFormPost`'s 64KiB peek, multipart, already-parsed PostForm, and body restore; switch the field it looks for. Keep it separate from `readFieldFromRequest`.
- Chosen: add the hidden input on stock, example, and e2e challenge forms (both checkbox and score branches of stock `captcha.html`).
- Chosen: delta live spec `core_plugin_middleware_captcha-routing` (and its usage Language); do not add a sibling spec or a Traefik knob.
- Rejected: renaming vendor TokenField on the challenge page — checkbox widgets inject `g-recaptcha-response` / siblings themselves (`ext_recaptcha_enterprise_widget`, `ext_eucaptcha_widget`).
- Rejected: a sibling peek reader that copies `form.go` — Consume before produce; the existing helper already exists because routing may still forward.
- Rejected: treating leftover-form as TokenField plus "no other app fields" — still collides with an application that embeds the same widget.
- Rejected: changing the first unsolved POST redirect URL — Out of scope.
- Live contract: `openspec/specs/core_plugin_middleware_captcha-routing/spec.md` (Requirement "Solved captcha-form POST does not reach origin" currently names the provider response field). Propose must delta it.

## Open questions

- Q: Who already owns the fact that a POST is the CrowdSec challenge form?
  Rank: bounded asked — existing `IsCaptchaFormPost` + TokenField contract with 1 production caller (`handleCaptchaKindServeHTTP` in `pkg/bouncer/bouncer.go`); roots `pkg/bouncer`, `pkg/captcha`, `tests/`, `knowledge/devdocs`, `openspec/specs`; Proposed solution and Why the signal is wrong name the owner move.
  Decision: assumed — after Check-true the plugin-owned hidden field is the owner; TokenField stays the first-solve Validate owner; Check stays the gate-cookie owner. Do not reconstruct leftover-form from the vendor field. Client address, Host, and trust hop are not reconstructed here (`clientrequest.Request` / `Check`).
  By: explore

- Q: Does Check-true marker detection reuse `IsCaptchaFormPost`'s 64KiB peek, multipart, and already-parsed PostForm rules, or a sibling reader?
  Rank: bounded asked — same 1 production caller plus 6 `Test_IsCaptchaFormPost*` tests and bouncer routing tests through that caller; roots as above; What stays the same / forward body included, and live spec "Captcha-form detection never costs origin its body".
  Decision: assumed — reuse that reader; change the field from TokenField to `crowdsec_captcha_challenge`; do not share it with `readFieldFromRequest`; empty TokenField must not gate marker detection.
  By: explore

- Q: Must the marker value be exactly `v1`, or is a non-empty field enough?
  Rank: additive asked — new field this change adds; Proposed solution HTML and decision tree name `crowdsec_captcha_challenge=v1`.
  Decision: assumed — exact value `v1`; missing, empty, or other values are application traffic on the Check-true branch.
  By: explore

- Q: Does any application already POST `crowdsec_captcha_challenge=v1`?
  Rank: additive asked — new field this change adds; Unknowns on requirement.md.
  Decision: assumed — no in-tree use of that name; CrowdSec-prefixed field is plugin-owned. An origin that posts it with a valid gate cookie is redirected; the marker grants nothing.
  By: explore

- Q: What happens to operator-replaced templates that omit the hidden field?
  Rank: additive asked — Templates section names the migration; not an unenumerated Go caller.
  Decision: assumed — first-solve still verifies TokenField; a second submit of that template is forwarded. Operators who want the duplicate-tab 302 add the same hidden input. Stock, examples, and e2e pages in this repo gain the field.
  By: explore

- Q: Is a new Traefik setting needed for the marker name or value?
  Rank: additive asked — Out of scope names "A new Traefik setting for the marker name or value."
  Decision: assumed — hardcoded name and `v1`; no Config key.
  By: explore

- Q: Keep `IsCaptchaFormPost` as the identifier after it stops reading TokenField?
  Rank: additive incidental — renaming is a means to the field change, not a named criterion.
  Decision: assumed — keep the identifier; retarget its comment and the usage Language **Solved-form POST** to the marker. Propose may rename if the identifier becomes a lie.
  By: explore
