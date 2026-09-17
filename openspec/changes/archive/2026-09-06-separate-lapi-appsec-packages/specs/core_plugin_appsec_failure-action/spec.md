## MODIFIED Requirements

### Requirement: CrowdsecAppsecFailureAction is the public AppSec fallback
Public config `crowdsecAppsecFailureAction` SHALL be one of `passthrough`, `ban`, or `captcha`. The default SHALL be `ban`. `captcha` SHALL be rejected at ValidateParams unless a captcha provider is configured. Empty SHALL be treated as `ban` (same as omit). Unknown values SHALL be rejected. This key SHALL be per-router (not on `lapi.Client` identity) so two routes can disagree on AppSec fallback against one LAPI.

#### Scenario: Default is ban
- **WHEN** the operator omits `crowdsecAppsecFailureAction` and AppSec returns HTTP 500
- **THEN** the client is forbidden (same as today’s `crowdsecAppsecFailureBlock` default true)

#### Scenario: Two routers may differ
- **WHEN** two middlewares share one `lapi.Client` and set different `crowdsecAppsecFailureAction` values
- **THEN** each route applies its own AppSec fallback
