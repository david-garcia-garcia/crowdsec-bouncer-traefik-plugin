## Context

See proposal.md. Dest leftover-form detection is `Client.IsCaptchaFormPost`: POST plus non-empty `widget.TokenField` in at most `captchaFormMaxBytes` (64KiB), urlencoded/multipart/already-parsed, body restored on no. The one production caller is `handleCaptchaKindServeHTTP` after `Check(req)` (`pkg/bouncer/bouncer.go`). First-solve stays `Validate` → `readFieldFromRequest(TokenField)`. `gatePayloadVersion` is `v1` on `crowdsec_captcha_gate` (`pkg/captcha/gate.go`) and is a different job. No Config key exists for a form marker.

## Goals / Non-Goals

**Goals:**
- Point leftover-form detection at one CrowdSec-owned marker.
- Keep the peek rules and the bouncer call sequence.
- Emit that marker from every shipped challenge page.

**Non-Goals:**
- Sharing leftover detection with `readFieldFromRequest` / `Validate`.
- Reusing `gatePayloadVersion`.
- A Traefik / plugin key for the marker.
- Renaming vendor `TokenField` names.
- A different URL for the first unsolved captcha 302.
- Changing `crowdsec_captcha_gate` HMAC or bind-IP rules.

## Decisions

1. **Same function, different field.** Keep `IsCaptchaFormPost` on `Client` and the bouncer call `Check(req)` then `IsCaptchaFormPost(req.Request)`. Change the lookup from `widget.TokenField` non-empty to leftover-form marker name `crowdsec_captcha_challenge` equal to `v1`. Drop the `TokenField == ""` early return; leftover detection MUST NOT depend on a vendor field being configured. Alternative: a second function next to `IsCaptchaFormPost` — rejected (`skill:opd-commandments:One job, one owner`; explore: migrate the one caller, signature stays). Alternative: TokenField fallback after the marker — rejected (requirement valid-gate branch reads the marker only).

2. **Constants live with leftover detection.** `pkg/captcha` owns `leftoverFormMarkerName` and `leftoverFormMarkerValue`. Shipped HTML emits those same literals. Tests compare HTML to the constants so the pages cannot drift. Do not read `gatePayloadVersion`. Do not add a Config key. Alternative: template placeholders for the name/value — rejected (Out of scope; no operator knob).

3. **Keep the peek.** `peekCaptchaFormBody` / `formFieldValue` stay the reader. `captchaFormMaxBytes` stays 64KiB. Already-parsed `PostForm` answers from parsed values. Over-cap bodies are not leftover forms even when they contain the marker name. Alternative: drop the cap because the ask HTML does not name it — rejected (live routing spec already promises the cap; recorded as a deviation).

4. **First-solve stays on TokenField.** `Validate` / `readFieldFromRequest` unchanged. Leftover detection stays a separate reader. Past-captcha stays `Check(req)` on the address `clientrequest.New` already chose; leftover detection MUST NOT re-derive address, Host, tenant, or trust hop.

5. **Shipped pages.** Add `<input type="hidden" name="crowdsec_captcha_challenge" value="v1">` inside the POST form on the six shipped challenge pages listed in the widget delta. A replaced template that omits it still first-solves; its second submit is forwarded.

## Risks / Trade-offs

- [Replaced templates lose duplicate-tab leftover redirect] → accepted; operators who still want it add the same hidden input. No TokenField fallback.
- [HTML literals drift from Go constants] → tests assert each shipped page contains `leftoverFormMarkerName` and `leftoverFormMarkerValue`.
- [A client that forges the marker only 302s its own POST] → accepted; passage still depends on the gate cookie.
- [Over-cap leftover form is forwarded] → accepted; same cap as today, origin body intact.

## Migration Plan

Deploy. First-solve needs no operator change. Operators with a replaced challenge template who still want leftover-tab redirect add the hidden input. Stock, example, and e2e pages ship it. No Config migration. Rollback is the previous plugin version; no persistent storage change.
