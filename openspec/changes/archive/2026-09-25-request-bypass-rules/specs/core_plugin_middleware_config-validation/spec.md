## REMOVED Requirements

### Requirement: Invalid exclude regex fails ValidateParams
**Reason**: The exclude strings are deleted. Compile and empty-rule rejection move to the bypass lists.
**Migration**: Put rules on `bouncerAppsecBypassRules` / `bouncerLapiBypassRules`. Invalid RE2 still fails `New`. Leftover exclude keys are ignored.

## ADDED Requirements

### Requirement: Invalid bypass rules fail ValidateParams
`ValidateParams` SHALL compile `BouncerAppsecBypassRules` and `BouncerLapiBypassRules` with the shared matcher constructor (`httprule.New`). An omitted or empty list SHALL pass (that setting is off). A rule SHALL fail when path, host, headers, and cookies are all absent (omitted or empty after trim / empty map) AND method is any (omitted, empty after trim, or a match-everything pattern such as `.*`). A method-only or host-only rule SHALL pass. `!!` SHALL fail. A leading `!` with an empty pattern SHALL fail. A method, path, host, header, or cookie pattern that Go `regexp.Compile` rejects SHALL fail. Error text SHALL name the Go field (`BouncerAppsecBypassRules` or `BouncerLapiBypassRules`). A `ValidateParams` failure from this rule SHALL cause `plugin.New` to return a nil handler and that error without opening LAPI. `bouncer.New` SHALL compile again to store the compiled set; ValidateParams discards the compiled value. The plugin MUST NOT ignore an invalid pattern.

#### Scenario: Empty lists pass
- **WHEN** `bouncerAppsecBypassRules` and `bouncerLapiBypassRules` are omitted or empty
- **THEN** `ValidateParams` returns no error from those fields

#### Scenario: Fully empty rule fails New
- **WHEN** `bouncerLapiBypassRules` contains `{}`
- **THEN** `ValidateParams` returns an error that names `BouncerLapiBypassRules`
- **AND** `New` returns a nil handler and that error
- **AND** it does not open LAPI

#### Scenario: Match-everything method with no other predicate fails
- **WHEN** `bouncerAppsecBypassRules` contains `{method: ".*"}`
- **THEN** `ValidateParams` returns an error that names `BouncerAppsecBypassRules`
- **AND** `New` returns a nil handler and that error

#### Scenario: Method-only rule passes
- **WHEN** `bouncerLapiBypassRules` contains `{method: "^OPTIONS$"}`
- **THEN** `ValidateParams` returns no error from that field

#### Scenario: Host-only rule passes
- **WHEN** `bouncerLapiBypassRules` contains `{host: "^probe\\.example$"}`
- **THEN** `ValidateParams` returns no error from that field

#### Scenario: Invalid host regexp fails New
- **WHEN** `bouncerLapiBypassRules` contains `{host: "("}`
- **THEN** `ValidateParams` returns an error that names `BouncerLapiBypassRules`
- **AND** `New` returns a nil handler and that error

#### Scenario: Double bang fails
- **WHEN** `bouncerLapiBypassRules` contains `{method: "!!POST"}`
- **THEN** `ValidateParams` returns an error that names `BouncerLapiBypassRules`

#### Scenario: Bang with empty pattern fails
- **WHEN** `bouncerLapiBypassRules` contains `{method: "!"}`
- **THEN** `ValidateParams` returns an error that names `BouncerLapiBypassRules`

#### Scenario: Invalid path regexp fails New
- **WHEN** `bouncerAppsecBypassRules` contains `{path: "("}`
- **THEN** `ValidateParams` returns an error that names `BouncerAppsecBypassRules`
- **AND** `New` returns a nil handler and that error
- **AND** it does not open LAPI

#### Scenario: Invalid method regexp fails New
- **WHEN** `bouncerLapiBypassRules` contains `{method: "("}`
- **THEN** `ValidateParams` returns an error that names `BouncerLapiBypassRules`
- **AND** `New` returns a nil handler and that error

#### Scenario: Valid rules pass
- **WHEN** `bouncerAppsecBypassRules` contains `{path: "^/healthz$"}` and `bouncerLapiBypassRules` contains `{method: "!POST", path: "^/admin/"}`
- **THEN** `ValidateParams` returns no error from those fields

## MODIFIED Requirements

### Requirement: ValidateParams test coverage for mode and helper gaps
The configuration package SHALL include unit tests covering: custom captcha provider missing fields; AppSec failure action `captcha` without a captcha instance name; **LAPI disabled AppSec-only path (replaces appsec mode without LAPI key)**; alone mode captcha key failures; empty or unloadable captcha and ban templates that warn and do not fail `New`; `GetTemplate` error paths; `validateURL` bad host; `BouncerRemediationStatusCode` bounds 99/600; `LapiUpdateMaxFailure: -1` acceptance; **instance name E2/E3 cases including captcha**; invalid `BouncerAppsecBypassRules` / `BouncerLapiBypassRules` that fail `ValidateParams`; empty lists that pass; fully empty rules and `.*` method-only-as-any that fail; method-only and host-only rules that pass.

#### Scenario: AppSec captcha without instance name rejected
- **WHEN** `bouncerAppsecFailureAction` is `captcha` and `captchaInstanceName` is empty after owner-fill rules
- **THEN** `ValidateParams` returns an error
