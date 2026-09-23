## MODIFIED Requirements

### Requirement: CrowdsecAppsecFailureAction is the public AppSec fallback
Public config `bouncerAppsecFailureAction` SHALL be one of `passthrough`, `ban`, or `captcha`. The default SHALL be `ban`. `captcha` SHALL be rejected at ValidateParams unless this router has a non-empty captcha instance name after owner-fill rules (`captchaEnabled` and empty name fills to the Traefik name). Empty SHALL be treated as `ban` (same as omit). Unknown values SHALL be rejected. This key SHALL be per-router (not on `lapi.Client` identity) so two routes can disagree on AppSec fallback against one LAPI. On `Bouncer` the field SHALL stay `appsecFailureAction`.

#### Scenario: Default is ban
- **WHEN** the operator omits `bouncerAppsecFailureAction` and AppSec returns HTTP 500
- **THEN** the client is forbidden (same as today’s `crowdsecAppsecFailureBlock` default true)

#### Scenario: Two routers may differ
- **WHEN** two middlewares share one `lapi.Client` and set different `bouncerAppsecFailureAction` values
- **THEN** each route applies its own AppSec fallback

#### Scenario: Captcha without instance name is invalid
- **WHEN** `bouncerAppsecFailureAction` is `captcha` and `captchaInstanceName` is empty after owner-fill rules
- **THEN** plugin initialization fails validation

### Requirement: Captcha failure action works in appsec mode
`bouncerAppsecFailureAction: captcha` SHALL serve the captcha challenge from the subscribed published captcha client in every `lapiMode`, AppSec-only included. `bouncer.New` MUST NOT construct a local captcha client for that action. `handleRemediationServeHTTP` SHALL ban when the loaded captcha client is empty or not valid. AppSec-only with `captcha` action SHALL subscribe to `captchaInstanceName` the same way any other bouncing router does.

#### Scenario: AppSec failure in AppSec-only with captcha action
- **WHEN** `lapiEnabled` is false, `appsecEnabled` is true, a captcha instance is published, `bouncerAppsecFailureAction` is `captcha`, and the AppSec listener returns HTTP 500
- **THEN** the client receives the captcha challenge
- **AND** the response is not a ban

#### Scenario: AppSec-only with ban action does not require a captcha subscribe
- **WHEN** `lapiEnabled` is false, `appsecEnabled` is true, and `bouncerAppsecFailureAction` is `ban` or omitted
- **THEN** the handler does not subscribe to captcha solely for that action
