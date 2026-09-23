## MODIFIED Requirements

### Requirement: CrowdsecLapiFailureAction is the public LAPI fallback
Public config `bouncerLapiFailureAction` SHALL be one of `passthrough`, `ban`, or `captcha`. The default SHALL be `ban`. `captcha` SHALL be rejected at ValidateParams unless this router has a non-empty captcha instance name after owner-fill rules (`captchaEnabled` and empty name fills to the Traefik name). Empty SHALL be treated as `ban` (same as omit). Unknown values SHALL be rejected. On `Bouncer` the field SHALL stay `lapiFailureAction`. A captcha verdict without a subscribed published client SHALL still ban at runtime.

#### Scenario: Default is ban
- **WHEN** the operator omits `bouncerLapiFailureAction`
- **THEN** live LAPI errors and stream-unhealthy cache misses ban as today

#### Scenario: Captcha without instance name is invalid
- **WHEN** `bouncerLapiFailureAction` is `captcha` and `captchaInstanceName` is empty after owner-fill rules
- **THEN** plugin initialization fails validation

#### Scenario: Owner omit is a legal captcha action
- **WHEN** `captchaEnabled` is true, `captchaInstanceName` is omitted, and `bouncerLapiFailureAction` is `captcha`
- **THEN** `ValidateParams` accepts the action
- **AND** the filled name is this middleware's Traefik name
