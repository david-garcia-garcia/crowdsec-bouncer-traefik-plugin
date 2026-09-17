## REMOVED Requirements

### Requirement: Captcha grace-done payload is owned by captcha
**Reason**: Captcha grace is stateless in the gate cookie; cache no longer stores captcha grace.
**Migration**: Operators rely on users re-solving captcha after deploy; stale `{ip}_captcha` keys are ignored by captcha `Check`.
