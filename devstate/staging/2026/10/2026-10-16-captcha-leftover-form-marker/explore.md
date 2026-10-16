# Explore

## Concepts

Leftover-form detection is one reader on one captcha-kind branch. It does not mint identity, and it does not verify a provider token.

```
handleCaptchaKindServeHTTP
        │
        ├─ IsCustomResourceRequest → continue (AppSec then origin)
        ├─ Check(req)  [crowdsec_captcha_gate vs inbound IP]
        │     ├─ true + IsCaptchaFormPost → WriteSolvedRedirect 302, origin not called
        │     └─ true otherwise → continue (AppSec then origin)
        └─ Check false → ServeHTTP → Validate(TokenField) / challenge page
```

Units this change would touch:

- `IsCaptchaFormPost` — `pkg/captcha/captcha.go` — leftover-form yes/no after `Check` is true. Today: non-empty `widget.TokenField` in a body of at most `captchaFormMaxBytes` (64KiB). Job after this change: non-empty `crowdsec_captcha_challenge=v1` under the same peek rules.
- `peekCaptchaFormBody` / `formFieldValue` — `pkg/captcha/form.go` — urlencoded and multipart peek that restores `Body` when the answer is no. Keep as the reader; change which field it looks up.
- `handleCaptchaKindServeHTTP` — `pkg/bouncer/bouncer.go` — the one production caller: `Check` then `IsCaptchaFormPost` then `WriteSolvedRedirect`. Sequence stays.
- `WriteSolvedRedirect` — `pkg/captcha/captcha.go` — 302 to `req.URL.String()`, `captcha:solved` header, no cookie remint, no siteverify. Unchanged.
- `Validate` / `readFieldFromRequest` — `pkg/captcha/captcha.go`, `pkg/captcha/form.go` — first-solve TokenField reader. Unchanged. Must not merge with leftover detection (live routing spec already forbids sharing).
- `Client.Check` / `crowdsec_captcha_gate` — `pkg/captcha/captcha.go`, `pkg/captcha/gate.go` — past-captcha owner. Unchanged.
- `clientrequest.Request` — `pkg/clientrequest/request.go` — inbound request plus GetRemoteIP address. Unchanged.
- Challenge templates — stock `captcha.html`, `examples/captcha/captcha.html`, `examples/custom-captcha/captcha.html`, `tests/e2e/real/config/captcha-dummy.html`, `tests/e2e/mock/scenarios/captcha/captcha.html`, `tests/e2e/mock/scenarios/captcha-ban-origins/captcha.html` — emit the hidden marker. None of these files contain `crowdsec_captcha_challenge` today.
- Widget pairing — `pkg/captcha/provider_siteverify.go`, `pkg/captcha/provider_enterprise.go`, `pkg/captcha/provider_eucaptcha.go` — TokenField names stay for first-solve only.

Call sites of leftover detection (`IsCaptchaFormPost`): **1** production caller (`pkg/bouncer/bouncer.go` `handleCaptchaKindServeHTTP`), definition in `pkg/captcha/captcha.go`. Tests: `pkg/captcha/zzz_routing_test.go`, `pkg/bouncer/zzz_captcha_routing_test.go`. Roots searched: worktree `**/*.go` for `IsCaptchaFormPost`. `WriteSolvedRedirect`: **1** production caller (same bouncer branch) plus definition and `pkg/captcha/zzz_routing_test.go`.

### Reproduce

Reproduced on this worktree.

1. `go test ./pkg/captcha/ ./pkg/bouncer/ -count=1 -run Test_IsCaptchaFormPost$|Test_IsCaptchaFormPost_ordinaryPostKeepsItsBody|TestHandleRemediationServeHTTP_solvedFormPostRedirects|TestHandleRemediationServeHTTP_ordinaryPostAfterSolveReachesOrigin` — pass.
   - Check-true POST with only the provider field: **302**, origin not called (`TestHandleRemediationServeHTTP_solvedFormPostRedirects`).
   - Check-true POST without the provider field: origin called, not 302 (`TestHandleRemediationServeHTTP_ordinaryPostAfterSolveReachesOrigin`).
2. Throwaway `IsCaptchaFormPost` against `Client.New` (custom, TokenField `dummy-captcha-response`), temp module outside the tree:
   - `username=alice&password=secret&dummy-captcha-response=vendor-token` → **true** (application POST collides with leftover detection).
   - `dummy-captcha-response=vendor-token` → true (leftover challenge).
   - `username=alice&password=secret` → false (ordinary app POST).

The detector cannot tell an application form that also carries the vendor token from a leftover CrowdSec challenge. Combined with (1), that mixed POST is the 302 that never reaches origin. Browser POST→GET on 302 was **not reproduced** (no browser this phase); the plugin 302 is what the tests measured.

### Outside facts

- In-tree TokenField names: `g-recaptcha-response` (classic + enterprise), `h-captcha-response`, `cf-turnstile-response`, `eu-captcha-response`, custom `CaptchaCustomResponse`.
- `knowledge/research/ext_recaptcha_enterprise_widget/`: checkbox POSTs `g-recaptcha-response` on form submit; score `execute` is JS; score **button** integration can still POST `g-recaptcha-response`.
- `knowledge/research/ext_eucaptcha_widget/`: `verify.js` injects hidden `eu-captcha-response` into the form that contains the widget.
- In-tree stock `captcha.html`: checkbox branch has no hidden token input (vendor script fills it); score branch has hidden `g-recaptcha-response` and `scoreBootScript` writes that field then submits.
- hCaptcha / Turnstile / classic v2 widget HTML injection: not in the research catalog at explore write time (siteverify notes only). Background research spawned; leftover detection after this change does not read those fields anyway.
- HTTP 302 method rewrite: not in `knowledge/research/` (only `ext_http_media-types/`). Not required to choose the marker seam.

## Decisions

- Chosen seam: after `Check` is true, `IsCaptchaFormPost` looks up hidden `crowdsec_captcha_challenge=v1` only, using the existing 64KiB urlencoded/multipart peek. `handleCaptchaKindServeHTTP` sequence stays. First-solve `Validate` still reads `TokenField`.
- Chosen templates: add the hidden input to the six shipped challenge pages listed above. No Traefik / plugin key.
- Rejected: rename vendor token fields — vendor checkbox scripts create those names; Out of scope.
- Rejected: keep TokenField as a fallback after the gate — requirement says the valid-gate branch reads the marker only; a fallback would keep mistaking application POSTs for leftover challenges.
- Rejected: drop the 64KiB peek cap — live routing spec `Captcha-form detection never costs origin its body` already promises the cap; the proposed HTML does not name dropping it.
- Rejected: share leftover detection with `readFieldFromRequest` / `Validate` — live spec forbids one helper; first-solve may consume the body, leftover detection may still forward it.
- Rejected: reuse `gatePayloadVersion` (`v1` on `crowdsec_captcha_gate`) as the form-marker value — same spelling, different job.
- Rejected: a different URL for the first unsolved captcha 302 — Out of scope.
- Live contract: `openspec/specs/core_plugin_middleware_captcha-routing/spec.md` (solved-form POST today is the provider field; this change MODIFIES that). Widget spec may gain the stock hidden input. Gate spec unchanged.

## Open questions

- Q: After the gate is valid, does leftover-form detection read only crowdsec_captcha_challenge=v1, not TokenField?
  Rank: bounded asked — existing IsCaptchaFormPost has 1 production caller in pkg/bouncer/bouncer.go handleCaptchaKindServeHTTP, searched Go files; requirement Proposed solution valid-gate branch names marker-only detection
  Decision: assumed — change IsCaptchaFormPost to that marker; migrate the bouncer caller (signature stays) and the routing tests in pkg/captcha and pkg/bouncer.
  By: explore
- Q: Do vendor widgets inject their token field into ordinary application POSTs in every provider mode?
  Rank: additive asked — no existing caller reshape; requirement Unknowns say Explore owns vendor facts
  Decision: assumed — checkbox widgets inject TokenField into the form that contains the widget (sourced: enterprise checkbox g-recaptcha-response; EU CAPTCHA eu-captcha-response; in-tree stock checkbox omits a hidden token). Score/execute can still POST g-recaptcha-response. After-gate detection must not use TokenField. First-solve still uses TokenField.
  By: explore
- Q: Should leftover detection keep the 64KiB peek cap in pkg/captcha/form.go?
  Rank: additive incidental — keeping the existing peek is not a reshape; no requirement line names dropping captchaFormMaxBytes
  Decision: assumed — keep captchaFormMaxBytes (64KiB) and the same urlencoded/multipart/already-parsed rules; look up the marker instead of TokenField.
  By: explore
- Q: What happens to a replaced operator template that omits the new hidden input?
  Rank: additive asked — Templates section: first submit still solves; second submit is forwarded
  Decision: assumed — honour that blast: no TokenField fallback. Operators who still want duplicate-tab redirect add the same hidden input.
  By: explore
- Q: Where does the marker name and value live so leftover detection and the shipped HTML stay one owner?
  Rank: additive asked — Proposed solution names crowdsec_captcha_challenge=v1; Out of scope forbids a Traefik key
  Decision: assumed — pkg/captcha owns the leftover-detection constant; shipped templates emit that same name and value. Do not share gatePayloadVersion. Do not add a Config key.
  By: explore
- Q: Who already owns past-captcha and the client address this path must not reconstruct?
  Rank: additive incidental — no identity unit is reshaped; explore identity gate, not a requirement criterion
  Decision: resolved — past-captcha is Client.Check on crowdsec_captcha_gate vs req.IPAddrString() from clientrequest.New after ip.GetRemoteIP. Leftover detection calls Check(req) and does not re-derive address, Host, tenant, or trust hop.
  By: explore
- Q: Does first-solve still verify the provider TokenField when the gate cookie is not valid?
  Rank: bounded asked — existing Validate / readFieldFromRequest callers stay; requirement When the gate cookie is not valid, request handling stays unchanged
  Decision: resolved — yes. ServeHTTP then Validate then readFieldFromRequest(TokenField) unchanged; leftover detection stays a separate reader.
  By: explore

