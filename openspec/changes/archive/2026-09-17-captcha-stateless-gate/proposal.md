## Why

Captcha grace after a successful provider solve is stored in the connection cache as `{ip}_captcha`. Grace therefore depends on cache reachability and shared-IP semantics, and cannot be carried as a portable browser credential. This change replaces cache grace with a signed HttpOnly cookie and drops captcha use of the cache.

## What Changes

- After successful provider verify, set cookie `crowdsec_captcha_gate` with HMAC-SHA256 payload `v1.<issued>.<bind>.<ip>.<sig>`; validate on later requests via `Check(r, remoteIP)`.
- New Traefik config: `captchaGateSecret` / `captchaGateSecretFile` (required when captcha enabled; not `CaptchaSecretKey`); `captchaGateBindIP` default true.
- Remove `CaptchaDoneValue`, `{ip}_captcha` cache writes/reads, and `*cache.Client` from `pkg/captcha` / bouncer wiring.
- Update OpenSpec cache isolated-store spec to stop requiring captcha grace keys in cache.
- **Not BREAKING** for remediation codes; stale cache grace keys no longer pass `Check` (intentional).

## Capabilities

### New Capabilities

- `core_plugin_middleware_captcha-gate`: Stateless signed cookie grace, config knobs, validation rules (expiry, skew, optional IP bind).

### Modified Capabilities

- `core_cache_client_isolated-store`: Remove requirement that captcha grace-done lives in cache; cache remains for decisions/stream lease only.

## Impact

- `pkg/captcha`, `pkg/bouncer`, `pkg/configuration`
- Tests in `pkg/captcha`, `pkg/bouncer`, configuration validation
- `openspec/specs/core_cache_client_isolated-store/spec.md`
- Operator examples mentioning captcha grace cache keys
