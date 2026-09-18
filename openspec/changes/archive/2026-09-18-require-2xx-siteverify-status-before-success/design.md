## Context

See `proposal.md` Why. Baseline is DestBranch `Validate` after `PostForm` (`pkg/captcha/captcha.go`): transport error returns `(false, err)`; a received response is accepted when `Content-Type` starts with `application/json` and decoded `success` is true; `res.StatusCode` is never read. `ServeHTTP` mints `crowdsec_captcha_gate` and 302s on `valid == true`. Explore reproduced HTTP 500 + JSON `{"success":true}` → 302 + gate cookie.

FindSpecHost:

```
verdicts:
  - { deltaId: require-2xx-siteverify-status, fold|new: new, spec-id: core_plugin_middleware_captcha-siteverify, confidence: high, candidates: [core_plugin_middleware_captcha-gate, core_plugin_middleware_captcha-routing, core_plugin_middleware_captcha-siteverify] }
```

Search: family `core_plugin_middleware` holds `captcha-gate` (cookie after successful provider verify — not what success means) and `captcha-routing` (routing after the gate). Siteverify HTTP acceptance has no owner. New leaf `captcha-siteverify`. Do not fold the status rule into `captcha-gate`. Do not revive PR #28's `core_plugin_captcha_handler` (not on dest).

## Goals / Non-Goals

**Goals:**

- Reject a received non-2xx siteverify status before Content-Type or decode.
- Return `(false, nil)` on that path so `ServeHTTP` re-renders the challenge at 200.
- Prove HTTP 500 + JSON `{"success":true}` does not mint the gate cookie or 302.

**Non-Goals:**

- Changing `PostForm` `err != nil` (PR #28).
- Changing Content-Type matching, body drain, or adding `remoteip` to the siteverify POST.
- Gate cookie format, bind-IP, HMAC, or captcha routing.
- Requiring the hunt name `TestHunt_siteverifyHTTPErrorDoesNotAcceptSuccessJSON`.
- A LAPI-style first-digit string check; numeric 200–299 is enough.

## Decisions

1. **Status band is `status >= 200 && status < 300`.** Same 2xx band as LAPI `crowdsecQuery` first-digit `2`, expressed on the int `StatusCode`. Alternative: 200 only — rejected; the requirement says 2xx. Alternative: copy LAPI's `strconv` first-digit test — rejected; that shape exists to format an error string, not because the digit is the owner.

2. **Check status immediately after `PostForm` succeeds, before Content-Type.** Requirement: require 2xx before decoding `success`. Alternative: decode first and ignore `success` on non-2xx — rejected; a non-2xx body must not be treated as a verdict.

3. **Non-2xx returns `(false, nil)`.** Same shape as the existing non-JSON Content-Type branch. `ServeHTTP` then writes 200 + challenge. Alternative: `(false, err)` → bare 400 — rejected; ticket and hunt only forbid cookie + solved 302, and failed verify already means re-render.

4. **Debug the status, sibling of `responseType:noJson`.** One Debug line that includes the status code. No new metric. Alternative: Info/Warn — rejected; Content-Type miss is Debug and this path is the same class of "not a solve".

5. **Keep the existing `defer` close. Do not add a drain.** Same as the Content-Type miss. LAPI-style drain is a different owner and out of scope.

6. **One path for every provider, including custom.** `Validate` already posts to `infoProvider.validate`. Do not split built-in vs custom.

7. **Regression lives under `pkg/captcha/` as `zzz_*_test.go`.** Prefer adding to `zzz_servehttp_test.go` (it already drives `ServeHTTP` against a stub siteverify). Assert status 200, no `crowdsec_captcha_gate`, not 302. Do not require the hunt function name.

8. **Reuse `remoteIP` already passed into `ServeHTTP`.** `Validate` does not choose identity. Do not add `remoteip` to the siteverify form in this change.

## Risks / Trade-offs

- [A siteverify that answers non-2xx with JSON `success: true` stops granting grace] → intentional; that is the defect.
- [A 2xx other than 200 with an empty or non-JSON body still follows dest Content-Type / decode] → out of scope; this change only adds the status gate.

## Migration Plan

Deploy the binary. No config key. Rollback is revert. Operators whose provider already answers 2xx + JSON `success` see no change.

## Open Questions

None — explore assumed policies apply; spec host resolved by FindSpecHost at propose.
