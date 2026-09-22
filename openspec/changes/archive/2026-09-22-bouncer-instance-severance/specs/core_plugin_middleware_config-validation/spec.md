## REMOVED Requirements

### Requirement: Appsec mode without AppSec warns and still starts
**Reason**: `crowdsecMode: appsec` is removed; LAPI-off AppSec-only is `crowdsecLapiEnabled: false` with AppSec enabled.
**Migration**: Replace `crowdsecMode: appsec` with `crowdsecLapiEnabled: false` and `crowdsecAppsecEnabled: true`.

## ADDED Requirements

### Requirement: Instance open versus subscribe validation
`ValidateParams` SHALL enforce the open-vs-subscribe matrix for each leg. When `enabled` is false and the leg enable flag is false, a non-empty instance name, API key, or client certificate for that leg SHALL fail validation (E2). When `enabled` is true, the leg enable flag is false, and the instance name is omitted after prepopulation rules, the bouncer SHALL NOT subscribe and validation SHALL succeed without treating the leg as open (E3). When a leg enable flag is true and neither API key nor client certificate can build that client, `ValidateParams` or subsequent `Open` failure SHALL fail `New` for that middleware.

#### Scenario: Leftover instance name with nothing enabled fails
- **WHEN** `enabled` is false, `crowdsecLapiEnabled` is false, and `crowdsecLapiInstanceName` is `shared`
- **THEN** `ValidateParams` returns an error

#### Scenario: Bouncer with LAPI leg off and no name succeeds
- **WHEN** `enabled` is true, `crowdsecLapiEnabled` is false, AppSec is disabled, and `crowdsecLapiInstanceName` is omitted
- **THEN** `ValidateParams` returns no error

### Requirement: crowdsecMode appsec value is rejected
`ValidateParams` SHALL reject `crowdsecMode: appsec` as an invalid mode value (E4). AppSec-only setups SHALL use `crowdsecLapiEnabled: false` instead.

#### Scenario: Legacy appsec mode fails startup
- **WHEN** `crowdsecMode` is `appsec`
- **THEN** `ValidateParams` returns an error

## MODIFIED Requirements

### Requirement: ValidateParams test coverage for mode and helper gaps
The configuration package SHALL include unit tests covering: custom captcha provider missing fields; AppSec failure action `captcha` without provider; **LAPI disabled AppSec-only path (replaces appsec mode without LAPI key)**; alone mode captcha/template failures; `GetTemplate` error paths; `validateURL` bad host; `RemediationStatusCode` bounds 99/600; `UpdateMaxFailure: -1` acceptance; **instance name E2/E3 cases**.

#### Scenario: AppSec captcha without provider rejected
- **WHEN** `crowdsecAppsecFailureAction` is `captcha` and `captchaProvider` is empty
- **THEN** `ValidateParams` returns an error
