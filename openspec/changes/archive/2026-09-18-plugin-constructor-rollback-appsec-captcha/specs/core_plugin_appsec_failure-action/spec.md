## ADDED Requirements

### Requirement: Captcha failure action works in appsec mode
`crowdsecAppsecFailureAction: captcha` SHALL serve the configured captcha challenge in every `crowdsecMode`, `appsec` included. `bouncer.New` MUST NOT return an appsec-mode handler whose captcha client is uninitialised while that action is `captcha`, because `handleRemediationServeHTTP` falls back to a ban when the captcha client is not valid. Initialising the captcha client for appsec mode SHALL be conditional on the effective AppSec failure action, so an appsec-mode router that cannot serve a challenge keeps today's early return.

#### Scenario: AppSec failure in appsec mode with captcha action
- **WHEN** `crowdsecMode` is `appsec`, `crowdsecAppsecEnabled` is true, a captcha provider is configured, `crowdsecAppsecFailureAction` is `captcha`, and the AppSec listener returns HTTP 500
- **THEN** the client receives the captcha challenge
- **AND** the response is not a ban

#### Scenario: Appsec mode with ban action keeps the early return
- **WHEN** `crowdsecMode` is `appsec` and `crowdsecAppsecFailureAction` is `ban` or omitted
- **THEN** the handler's captcha client is not initialised
