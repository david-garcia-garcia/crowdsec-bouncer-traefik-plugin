## Purpose

Startup validation for plugin configuration in `pkg/configuration.ValidateParams`.

## Requirements

### Requirement: AppSec URL uses effective scheme
`ValidateParams` SHALL validate the AppSec URL using the effective AppSec scheme: `crowdsecAppsecScheme` when non-empty, otherwise `crowdsecLapiScheme`. It MUST NOT pass `crowdsecLapiScheme` when AppSec has its own scheme. This URL check SHALL run only when `crowdsecAppsecEnabled` is true.

#### Scenario: Distinct AppSec HTTPS scheme
- **WHEN** `crowdsecAppsecEnabled` is true, `crowdsecAppsecScheme` is `https` and `crowdsecLapiScheme` is `http`
- **THEN** AppSec URL validation uses `https://` format
- **AND** an invalid AppSec host fails at `ValidateParams`

### Requirement: AppSec HTTPS CA validated at startup
When `crowdsecAppsecEnabled` is true, `crowdsecAppsecScheme` is explicitly set to `https`, and `crowdsecAppsecTlsInsecureVerify` is false, `ValidateParams` SHALL parse `crowdsecAppsecTlsCertificateAuthority` PEM when provided, rejecting invalid PEM the same way LAPI CA is rejected today.

#### Scenario: Invalid AppSec CA with LAPI HTTP
- **WHEN** `crowdsecAppsecEnabled` is true, `crowdsecLapiScheme` is `http`, `crowdsecAppsecScheme` is `https`, and AppSec CA PEM is garbage
- **THEN** `ValidateParams` returns an error

### Requirement: Alone mode validates captcha templates and logging
In `crowdsecMode: alone`, `ValidateParams` SHALL still validate captcha site/secret keys when a captcha provider is configured, captcha/ban template files when paths are set, and log level / writable log file path. It MAY skip LAPI URL, LAPI key, and LAPI TLS checks after CAPI credential validation. Empty site or secret after file-then-field lookup SHALL fail even when `CaptchaGateSecret` is set. When `crowdsecAppsecEnabled` is true, it SHALL still validate AppSec URL, AppSec key, and AppSec HTTPS CA.

#### Scenario: Alone mode missing captcha keys
- **WHEN** mode is `alone`, failure action is `captcha`, provider is set, `CaptchaGateSecret` is set, and site/secret keys are empty
- **THEN** `ValidateParams` returns an error that names `CaptchaSiteKey` cannot be empty

#### Scenario: Alone mode invalid log level
- **WHEN** mode is `alone` and log level is not one of DEBUG/INFO/WARN/ERROR
- **THEN** `ValidateParams` returns an error

### Requirement: Appsec mode without AppSec warns and still starts
`crowdsecMode: appsec` with `crowdsecAppsecEnabled: false` selects no decision source and no WAF leg, so the middleware enforces nothing. `ValidateParams` SHALL log a warning for that combination and SHALL still accept the configuration. It MUST NOT return an error, and it MUST NOT imply `crowdsecAppsecEnabled` on (`crowdsecAppsecHost` defaults to `crowdsec:7422` and `crowdsecAppsecFailureAction` defaults to `ban`, so implying it would ban every request on that router against a listener that may not exist). The warning SHALL be emitted at `WARN`, so it is visible at the default log level, and SHALL name both keys and say that no request is checked in this state.

#### Scenario: Appsec mode with AppSec disabled
- **WHEN** `crowdsecMode` is `appsec` and `crowdsecAppsecEnabled` is false
- **THEN** `ValidateParams` returns no error
- **AND** it logs a `WARN` naming `crowdsecMode` and `crowdsecAppsecEnabled` and stating that nothing is enforced

#### Scenario: Appsec mode with AppSec enabled is silent
- **WHEN** `crowdsecMode` is `appsec` and `crowdsecAppsecEnabled` is true
- **THEN** `ValidateParams` logs no such warning

### Requirement: ValidateParams test coverage for mode and helper gaps
The configuration package SHALL include unit tests covering: custom captcha provider missing fields; AppSec failure action `captcha` without provider; `appsec` mode without LAPI key; alone mode captcha/template failures; `GetTemplate` error paths; `validateURL` bad host; `RemediationStatusCode` bounds 99/600; `UpdateMaxFailure: -1` acceptance.

#### Scenario: AppSec captcha without provider rejected
- **WHEN** `crowdsecAppsecFailureAction` is `captcha` and `captchaProvider` is empty
- **THEN** `ValidateParams` returns an error

### Requirement: Redis password file resolved only when Redis is enabled
`ValidateParams` SHALL resolve `RedisCachePassword` and `RedisCachePasswordFile` only when `redisCacheEnabled` is true. When `redisCacheEnabled` is false, a missing, directory, or unreadable `redisCachePasswordFile` MUST NOT fail startup. When `redisCacheEnabled` is true, a non-empty `redisCachePasswordFile` that is missing, a directory, or unreadable SHALL fail startup. An empty password with an empty file path SHALL still be accepted when Redis is enabled.

#### Scenario: Disabled Redis ignores a missing password file
- **WHEN** `redisCacheEnabled` is false and `redisCachePasswordFile` names a path that does not exist
- **THEN** `ValidateParams` returns no error

#### Scenario: Disabled Redis ignores a stale password file
- **WHEN** `redisCacheEnabled` is false and `redisCachePasswordFile` names a directory or an unreadable path
- **THEN** `ValidateParams` returns no error

#### Scenario: Enabled Redis still rejects a missing password file
- **WHEN** `redisCacheEnabled` is true and `redisCachePasswordFile` names a path that does not exist
- **THEN** `ValidateParams` returns an error

#### Scenario: Enabled Redis accepts an empty password with no file
- **WHEN** `redisCacheEnabled` is true, `redisCachePassword` is empty, and `redisCachePasswordFile` is empty
- **THEN** `ValidateParams` returns no error

### Requirement: Enabled AppSec requires a listener host
When `crowdsecAppsecEnabled` is true, `ValidateParams` SHALL reject an empty `crowdsecAppsecHost` and any AppSec URL that `http.NewRequest` accepts only because the host is missing. When `crowdsecAppsecEnabled` is false, `ValidateParams` MUST NOT fail solely because `crowdsecAppsecHost` is empty. Shared LAPI URL validation MUST keep accepting an empty host the same way it does today.

#### Scenario: Enabled AppSec with empty host is rejected
- **WHEN** `crowdsecAppsecEnabled` is true and `crowdsecAppsecHost` is empty
- **THEN** `ValidateParams` returns an error

#### Scenario: Disabled AppSec with empty host is accepted
- **WHEN** `crowdsecAppsecEnabled` is false, `crowdsecAppsecHost` is empty, and the rest of the config is valid
- **THEN** `ValidateParams` returns nil

### Requirement: Reject empty captcha site and secret after lookup
When `captchaProvider` is set, `ValidateParams` SHALL resolve `CaptchaSiteKey` and `CaptchaSecretKey` with the same file-then-field lookup used for `CaptchaGateSecret`. After a successful lookup it SHALL reject an empty trimmed string for each field independently, site first. The trigger is a non-empty provider, not a captcha failure action. Error text SHALL be `CaptchaSiteKey: cannot be empty when CaptchaProvider is set` and `CaptchaSecretKey: cannot be empty when CaptchaProvider is set`. A `ValidateParams` failure from this rule SHALL cause `New` to return a nil handler and that error without opening LAPI.

#### Scenario: Provider set with empty site and secret
- **WHEN** `captchaProvider` is set, `CaptchaGateSecret` is set, and both site and secret resolve empty
- **THEN** `ValidateParams` returns `CaptchaSiteKey: cannot be empty when CaptchaProvider is set`

#### Scenario: Only site empty
- **WHEN** `captchaProvider` is set, secret is non-empty, and site resolves empty
- **THEN** `ValidateParams` returns `CaptchaSiteKey: cannot be empty when CaptchaProvider is set`

#### Scenario: Only secret empty
- **WHEN** `captchaProvider` is set, site is non-empty, and secret resolves empty
- **THEN** `ValidateParams` returns `CaptchaSecretKey: cannot be empty when CaptchaProvider is set`

#### Scenario: Whitespace-only site is empty
- **WHEN** `captchaProvider` is set and site is only whitespace
- **THEN** `ValidateParams` returns `CaptchaSiteKey: cannot be empty when CaptchaProvider is set`

#### Scenario: Default ban action still rejects empty keys
- **WHEN** `captchaProvider` is set, failure actions are the default `ban`, and site/secret resolve empty
- **THEN** `ValidateParams` returns an error that names the empty site key

#### Scenario: New returns no handler
- **WHEN** `New` is called with `captchaProvider` set, `CaptchaGateSecret` set, and empty site key
- **THEN** `New` returns a nil handler and an error
- **AND** it does not open LAPI

### Requirement: AppSec URL key and HTTPS CA validated only when enabled
When `crowdsecAppsecEnabled` is true, `ValidateParams` SHALL validate AppSec URL (effective scheme), AppSec key file-then-field lookup, and AppSec HTTPS CA PEM (explicit `https` scheme and insecure-verify false) in every `crowdsecMode`. When `crowdsecAppsecEnabled` is false, it MUST NOT validate AppSec host, URL, key, or CA, even if leftover fields are set. Alone mode SHALL still skip LAPI URL, LAPI key, and LAPI TLS after CAPI machine id and password. Live, stream, none, and appsec modes SHALL still validate LAPI. An empty AppSec key after a successful lookup SHALL still pass.

#### Scenario: Alone AppSec on with invalid CA
- **WHEN** mode is `alone`, CAPI machine id and password are set, `crowdsecAppsecEnabled` is true, `crowdsecAppsecScheme` is `https`, and AppSec CA PEM is garbage
- **THEN** `ValidateParams` returns an error

#### Scenario: Alone AppSec on with missing key file
- **WHEN** mode is `alone`, CAPI machine id and password are set, `crowdsecAppsecEnabled` is true, and `crowdsecAppsecKeyFile` names a missing path
- **THEN** `ValidateParams` returns an error that names `CrowdsecAppsecKey` and an invalid path

#### Scenario: Alone AppSec off leftover CA and key file
- **WHEN** mode is `alone`, CAPI machine id and password are set, `crowdsecAppsecEnabled` is false, AppSec CA PEM is garbage, and `crowdsecAppsecKeyFile` names a missing path
- **THEN** `ValidateParams` returns no error

#### Scenario: Live AppSec off leftover CA and key file
- **WHEN** mode is `live` or `stream`, LAPI is valid, `crowdsecAppsecEnabled` is false, AppSec CA PEM is garbage, and `crowdsecAppsecKeyFile` names a missing path
- **THEN** `ValidateParams` returns no error

#### Scenario: Live AppSec on with invalid CA
- **WHEN** mode is `live` or `stream`, LAPI is valid, `crowdsecAppsecEnabled` is true, `crowdsecAppsecScheme` is `https`, and AppSec CA PEM is garbage
- **THEN** `ValidateParams` returns an error

#### Scenario: Live AppSec on with missing key file
- **WHEN** mode is `live` or `stream`, LAPI is valid, `crowdsecAppsecEnabled` is true, and `crowdsecAppsecKeyFile` names a missing path
- **THEN** `ValidateParams` returns an error that names `CrowdsecAppsecKey` and an invalid path

### Requirement: Shared backend backoff knobs default to the published package
Public config SHALL expose one shared knob set applied independently when each Client constructs its Gate: `backendBackoffFailureRatio` (default `0.30`), `backendBackoffTripFailures` (default `5`), `backendBackoffBaseCooldownSeconds` (default `1`), `backendBackoffMaxCooldownSeconds` (default `10`), `backendBackoffJitter` (default `0.10`), `backendBackoffTTLSeconds` (default `60`). `CreateConfig` / `configuration.New` SHALL set those defaults so a fully populated Config is always passed and a zero `Jitter` is not an accidental omit. There SHALL be no product enabled flag. `Jitter` `0` disables jitter only. README SHALL document the keys and those defaults. LAPI and AppSec MUST NOT grow separate knob sets.

#### Scenario: Omitted knobs use package defaults
- **WHEN** the operator omits every `backendBackoff*` key
- **THEN** `CreateConfig` supplies FailureRatio `0.30`, TripFailures `5`, BaseCooldown `1s`, MaxCooldown `10s`, Jitter `0.10`, and TTL `60s`

#### Scenario: Explicit jitter zero disables jitter only
- **WHEN** the operator sets `backendBackoffJitter` to `0` and leaves the other knobs at defaults
- **THEN** `ValidateParams` accepts the config
- **AND** the constructed Gates disable jitter only

### Requirement: ValidateParams rejects values the published Gate would reject
`ValidateParams` SHALL reject a backoff Config that `backendbackoff.New` would reject: FailureRatio not in `(0, 1)` after the library's zero-fill, TripFailures `< 1` after zero-fill, BaseCooldown `≤ 0`, MaxCooldown `<` BaseCooldown, Jitter not in `[0, 1)`, or TTL `< 1s`. A `ValidateParams` failure from this rule SHALL cause `New` to return a nil handler and that error without opening LAPI. Validation SHALL run in every `crowdsecMode`.

#### Scenario: FailureRatio out of range is rejected
- **WHEN** `backendBackoffFailureRatio` is `1.5`
- **THEN** `ValidateParams` returns an error

#### Scenario: MaxCooldown below BaseCooldown is rejected
- **WHEN** `backendBackoffBaseCooldownSeconds` is `10` and `backendBackoffMaxCooldownSeconds` is `1`
- **THEN** `ValidateParams` returns an error

#### Scenario: New returns no handler
- **WHEN** `New` is called with `backendBackoffFailureRatio` `1.5` and an otherwise valid config
- **THEN** `New` returns a nil handler and an error
- **AND** it does not open LAPI
