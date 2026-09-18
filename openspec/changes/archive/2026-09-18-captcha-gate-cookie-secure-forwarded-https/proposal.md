## Why

After a captcha solve, `setGateCookie` sets `Secure` only when `r.TLS != nil`. Behind Cloudflare or an ALB, Traefik sees `TLS == nil` and a kept `X-Forwarded-Proto: https`, so `crowdsec_captcha_gate` is issued without `Secure` and a browser may send grace on a same-host HTTP entrypoint.

## What Changes

- Set `crowdsec_captcha_gate` `Secure` when `r.TLS != nil` **or** the request's `X-Forwarded-Proto` (as Traefik's entrypoint left it) is `https`.
- Keep the decision inside `setGateCookie` from `r` alone. Do not add hop-trust fields to `captcha.Client`, do not copy `GetRemoteIP`'s CIDR walk, and do not change client-address selection.
- Add `pkg/captcha` gate tests for forwarded-https + `TLS == nil`, TLS-on, and proto `http` / absent.
- Update `core_plugin_middleware_captcha-gate` so Secure is TLS **or** forwarded https. Other cookie attributes stay as specified.
- **Not BREAKING.** Cookie name, Path, HttpOnly, SameSite, MaxAge, Domain, HMAC, and bind-IP are unchanged.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_captcha-gate`: Secure is required when the request is TLS **or** Traefik-sanitized `X-Forwarded-Proto` is `https`.

## Impact

- `pkg/captcha/gate.go` (`setGateCookie`)
- `pkg/captcha` gate tests (`Test_setGateCookie_…` in `zzz_gate_test.go`)
- `openspec/specs/core_plugin_middleware_captcha-gate/spec.md`
- Usage packet `knowledge/devdocs/core_plugin_middleware_captcha-gate.md` does not mention Secure; leave that for implement / devdocs-impact
