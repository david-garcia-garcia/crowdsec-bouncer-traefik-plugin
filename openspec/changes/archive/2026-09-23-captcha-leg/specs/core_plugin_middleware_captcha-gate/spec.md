## MODIFIED Requirements

### Requirement: Gate secret is dedicated and required when captcha is enabled
When `captchaEnabled` is true, the plugin SHALL require a non-empty gate HMAC secret from `BouncerCaptchaGateSecret` or `BouncerCaptchaGateSecretFile` (via existing variable resolution). The gate secret MUST NOT be derived from `CaptchaSecretKey` or the LAPI key. A subscriber leftover provider MUST NOT require a gate secret on that router.

#### Scenario: Enabled captcha without gate secret fails validation
- **WHEN** `captchaEnabled` is true
- **AND** gate secret resolves empty after file/env lookup
- **THEN** configuration validation rejects the middleware

#### Scenario: Subscriber leftover provider does not require gate secret
- **WHEN** `captchaEnabled` is false and leftover `bouncerCaptchaProvider` is set
- **AND** gate secret resolves empty
- **THEN** configuration validation does not fail from this rule
