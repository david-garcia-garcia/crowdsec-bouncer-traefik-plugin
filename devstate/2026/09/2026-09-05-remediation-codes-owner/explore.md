# Explore

## Concepts

```
  LAPI type "ban"/"captcha"
            │
            ▼
  decisionscope.RemediationValue  ──►  wire byte in cache.Client
            │                              t | c | f
            ▼
  bouncer.ServeHTTP / captcha.Check
            │
            ▼
  captcha grace key {ip}_captcha  ──►  d  (captcha.CaptchaDoneValue)
```

**Remediation bytes** (`t` / `c` / `f`) are this plugin's cache payloads for ban, captcha, and none. CrowdSec LAPI still speaks `ban` / `captcha`. `pkg/decisionscope` already maps those types (`RemediationValue`) and prefers ban (`PreferRemediation`, `IsActiveRemediation`). The bytes today are declared on `pkg/cache`.

**Captcha grace-done** (`d`) is not a CrowdSec decision. `pkg/captcha` writes `{ip}_captcha` after a solved challenge and `Check` compares that value. Cache is only the store.

**String KV** (`pkg/cache`): Get / Set / Delete / GetMany plus `CacheMiss` / `CacheUnreachable`. Isolated Client (memory map or Redis prefix). Not CrowdSec vocabulary.

**Stream lease**: key `updated` is Set with `NoBannedValue` (`f`). `Get` only tests presence. Existing Redis leases stay valid if the payload stays `f`.

Bouncer, crowdsecconnection, decisionscope, and captcha already import `cache.Client` and/or `CacheMiss`. Moving the consts does not drop those imports. Bouncer and crowdsecconnection already import `decisionscope`.

No `pkg/remediation`. `lookup.go` already owns the mapping functions; the three ban/captcha/none consts sit next to them. `CaptchaDoneValue` sits on `pkg/captcha`.

This change does not compute client address, user, tenant, Host, or trust hop. Remote IP stays `pkg/ip.GetRemoteIP`.

## Decisions

- Ban / captcha / none consts move to `pkg/decisionscope` as `BannedValue`, `CaptchaValue`, `NoBannedValue` with values `t` / `c` / `f`.
- Grace-done moves to `pkg/captcha` as `CaptchaDoneValue` with value `d`.
- `pkg/cache` drops those four consts; keep `CacheMiss` / `CacheUnreachable` and the Client API.
- Call sites switch owners. `pkg/cache` tests use opaque string literals (no import of decisionscope).
- Stream lease keeps writing `f` via `decisionscope.NoBannedValue` (presence-only Get).
- Do not invent `pkg/remediation`. Do not split `connection.go`. Do not drop `configuration` from decisionscope. Do not change Redis/memory behavior.
- No new Language term this run. Usage packets already say ban/captcha remediations; owner sentences are a later usage fix if the packets still imply cache owns the bytes.

## Open questions

- Q: Should `pkg/cache` tests import `decisionscope` for sample payloads?
  Decision: resolved — no; use opaque string literals so the store package does not depend on decisionscope.
  By: explore

- Q: Where in `pkg/decisionscope` do `BannedValue` / `CaptchaValue` / `NoBannedValue` live?
  Decision: resolved — package consts next to `RemediationValue` in `lookup.go` (same domain as LAPI type mapping).
  By: explore

- Q: Keep the identifier names `BannedValue`, `CaptchaValue`, `NoBannedValue`, `CaptchaDoneValue`?
  Decision: resolved — keep; the ticket names them. Wire bytes stay `t` / `c` / `f` / `d`.
  By: explore

- Q: After the move, does `pkg/captcha` import `decisionscope`?
  Decision: resolved — no; captcha only owns `CaptchaDoneValue` and still uses `cache.Client` for the grace key.
  By: explore

- Q: Who already owns client identity for this change?
  Decision: resolved — this change does not set identity. Client IP stays `pkg/ip.GetRemoteIP`. Do not reconstruct it.
  By: explore

- Q: Stream lease key `updated` currently stores `NoBannedValue`. Should it get its own token?
  Decision: assumed — keep writing `f` via `decisionscope.NoBannedValue`. Get only checks presence; a new token would be extra surface. Existing Redis leases stay `f`.
  By: explore

- Q: Invent a Language term for the one-byte cache payloads?
  Decision: assumed — do not invent a term this run. Ban / captcha / none stay the names. Devdocs impact updates owner sentences if usage still points at cache.
  By: explore
