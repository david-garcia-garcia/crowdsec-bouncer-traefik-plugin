## Context

See proposal.md — Why. Today `pkg/cache` declares `BannedValue` (`t`), `NoBannedValue` (`f`), `CaptchaValue` (`c`), and `CaptchaDoneValue` (`d`). `pkg/decisionscope` already maps LAPI `ban`/`captcha` via `RemediationValue` and prefers ban. `pkg/captcha` writes `{ip}_captcha` after a solved challenge. Bouncer and crowdsecconnection already import `decisionscope` and still need `cache.Client` / `CacheMiss`. Stream lease key `updated` Sets `f`; Get only checks presence. Client IP stays `pkg/ip.GetRemoteIP`.

## Goals / Non-Goals

**Goals:**
- Ban / captcha / none codes live on `pkg/decisionscope` with wire `t` / `c` / `f`.
- Grace-done lives on `pkg/captcha` with wire `d`.
- `pkg/cache` is a string KV only.
- Existing Redis/memory entries stay valid.

**Non-Goals:**
- `pkg/remediation`.
- Splitting `connection.go`.
- Dropping `pkg/configuration` from `pkg/decisionscope`.
- Changing Redis vs memory behavior, key prefixing, or Get/Set/Delete/GetMany.
- A new stream-lease token (keep writing `f`).
- Sibling tickets (connection split, configuration split, IP trust, scope headers identity, decisionscope mode bool, config prepare snapshot).

## Decisions

1. **Consts sit next to `RemediationValue` in `lookup.go`.** Same domain as LAPI type mapping. Alternative: `codes.go` — extra file for three strings. Alternative: `pkg/remediation` — forbidden by the ticket.

2. **`CaptchaDoneValue` sits on `pkg/captcha`.** Captcha does not import `decisionscope` for this. Alternative: put `d` on decisionscope — rejected; grace-done is not a CrowdSec decision.

3. **`pkg/cache` tests use opaque literals.** The store package MUST NOT import decisionscope.

4. **Stream lease keeps `decisionscope.NoBannedValue`.** Get ignores the value. A new lease token is extra surface.

5. **Identity:** reuse `pkg/ip.GetRemoteIP`. Do not reconstruct client address.

## Risks / Trade-offs

- [Missed call site still uses `cache.BannedValue`] → compile fail after the consts move.
- [Yaegi / plugin tests import cache only for the const] → switch `plugin_test.go` to `decisionscope.BannedValue`; it still uses `cache.Client` for Get.
- [Lease payload change would invalidate nothing if Get is presence-only, but we keep `f` anyway] → wire compatibility.

## Migration Plan

Plugin version bump. No new YAML keys. Rollback is the previous tag. Redis/memory payloads are unchanged.

## Open Questions

Assumed proceed policies live on `devstate/explore.md` (lease keeps `f`; no new Language term).
