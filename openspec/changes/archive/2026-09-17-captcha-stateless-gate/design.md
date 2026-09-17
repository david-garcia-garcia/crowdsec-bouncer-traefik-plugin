## Context

See proposal.md. Today `pkg/captcha` writes `{remoteIP}_captcha` = `d` on solve and `Check(remoteIP)` reads cache. Bouncer passes `req.remoteIP` from `GetRemoteIP` once. Explore fixed cookie encoding, config keys, and cache removal (`devstate/explore.md`).

## Goals / Non-Goals

**Goals:**
- Issue and validate `crowdsec_captcha_gate` with dedicated HMAC secret.
- `Check(r, remoteIP)` reads cookie only; no cache dependency in captcha.
- Config validation requires gate secret when captcha provider is set.

**Non-Goals:**
- Removing Redis/decision cache elsewhere.
- UA or HTTP protocol binding (#353).
- Merging PR #45 cache-token sessions.

## Decisions

1. **Payload** `v1.<unix_issued>.<0|1>.<ip>.<base64url_hmac>` where HMAC key is gate secret bytes; prefix for MAC is everything before the final dot.
2. **Cookie attrs** HttpOnly, Path=/, SameSite=Lax, MaxAge=grace, Secure iff `r.TLS != nil`, no Domain.
3. **IP bind** compare opaque strings to bouncer `remoteIP`; no re-parse in captcha.
4. **New file** `pkg/captcha/gate.go` for mint/parse; keep `captcha.go` for provider/template flow.
5. **Configuration** fields on existing Configuration struct with `GetVariable` for secret file.

## Risks / Trade-offs

- [Stale cache grace stops working] → intentional; operators accept re-solve after deploy.
- [Secret rotation invalidates cookies] → document; same as any HMAC gate.

## Migration Plan

Deploy with `captchaGateSecret` set. Legacy cache keys ignored. Close PR #45 without merge.

## Open Questions

None — explore assumed policies apply.
