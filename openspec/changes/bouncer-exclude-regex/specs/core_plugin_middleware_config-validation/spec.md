## ADDED Requirements

### Requirement: Invalid exclude regex fails ValidateParams
`ValidateParams` SHALL trim `BouncerAppsecExcludeRegex` and `BouncerLapiExcludeRegex`. Empty after trim SHALL pass (that setting is off; do not compile). A non-empty string that Go `regexp.Compile` rejects SHALL fail `ValidateParams`. Error text SHALL name the Go field. A `ValidateParams` failure from this rule SHALL cause `plugin.New` to return a nil handler and that error without opening LAPI. `bouncer.New` SHALL compile again to store the `*regexp.Regexp`; ValidateParams discards the compiled value. The plugin MUST NOT ignore an invalid pattern.

#### Scenario: Empty exclude strings pass
- **WHEN** `bouncerAppsecExcludeRegex` and `bouncerLapiExcludeRegex` are omitted or empty
- **THEN** `ValidateParams` returns no error from those fields

#### Scenario: Whitespace-only exclude is off
- **WHEN** `bouncerLapiExcludeRegex` is only whitespace
- **THEN** `ValidateParams` returns no error from that field

#### Scenario: Invalid AppSec regex fails New
- **WHEN** `bouncerAppsecExcludeRegex` is `(`
- **THEN** `ValidateParams` returns an error that names `BouncerAppsecExcludeRegex`
- **AND** `New` returns a nil handler and that error
- **AND** it does not open LAPI

#### Scenario: Invalid LAPI regex fails New
- **WHEN** `bouncerLapiExcludeRegex` is `(`
- **THEN** `ValidateParams` returns an error that names `BouncerLapiExcludeRegex`
- **AND** `New` returns a nil handler and that error

#### Scenario: Valid regex passes
- **WHEN** `bouncerAppsecExcludeRegex` is `example\.com/health` and `bouncerLapiExcludeRegex` is `^ok/`
- **THEN** `ValidateParams` returns no error from those fields

## MODIFIED Requirements

### Requirement: ValidateParams test coverage for mode and helper gaps
The configuration package SHALL include unit tests covering: custom captcha provider missing fields; AppSec failure action `captcha` without a captcha instance name; **LAPI disabled AppSec-only path (replaces appsec mode without LAPI key)**; alone mode captcha key failures; empty or unloadable captcha and ban templates that warn and do not fail `New`; `GetTemplate` error paths; `validateURL` bad host; `BouncerRemediationStatusCode` bounds 99/600; `LapiUpdateMaxFailure: -1` acceptance; **instance name E2/E3 cases including captcha**; invalid `BouncerAppsecExcludeRegex` / `BouncerLapiExcludeRegex` that fail `ValidateParams`; empty or whitespace-only exclude strings that pass.

#### Scenario: AppSec captcha without instance name rejected
- **WHEN** `bouncerAppsecFailureAction` is `captcha` and `captchaInstanceName` is empty after owner-fill rules
- **THEN** `ValidateParams` returns an error
