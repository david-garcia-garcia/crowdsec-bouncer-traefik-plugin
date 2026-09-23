## Purpose

Startup validation for plugin configuration in `pkg/configuration.ValidateParams`.

## Requirements

### Requirement: AppSec URL uses effective scheme
`ValidateParams` SHALL validate the AppSec URL using the effective AppSec scheme: `appsecScheme` when non-empty, otherwise `lapiScheme`. It MUST NOT pass `lapiScheme` when AppSec has its own scheme. This URL check SHALL run only when `appsecEnabled` is true.

#### Scenario: Distinct AppSec HTTPS scheme
- **WHEN** `appsecEnabled` is true, `appsecScheme` is `https` and `lapiScheme` is `http`
- **THEN** AppSec URL validation uses `https://` format
- **AND** an invalid AppSec host fails at `ValidateParams`

### Requirement: AppSec HTTPS CA validated at startup
When `appsecEnabled` is true, `appsecScheme` is explicitly set to `https`, and `appsecTlsInsecureVerify` is false, `ValidateParams` SHALL parse `appsecTlsCertificateAuthority` PEM when provided, rejecting invalid PEM the same way LAPI CA is rejected today.

#### Scenario: Invalid AppSec CA with LAPI HTTP
- **WHEN** `appsecEnabled` is true, `lapiScheme` is `http`, `appsecScheme` is `https`, and AppSec CA PEM is garbage
- **THEN** `ValidateParams` returns an error

### Requirement: Alone mode validates captcha templates and logging
In `lapiMode: alone`, `ValidateParams` SHALL still validate captcha site/secret keys when a captcha provider is configured, the captcha template when a provider is set (empty `BouncerCaptchaFilePath` or a `GetTemplate` failure SHALL fail), the ban template when that path is set, and log level / writable log file path. It MAY skip LAPI URL, LAPI key, and LAPI TLS checks after CAPI credential validation. Empty site or secret after file-then-field lookup SHALL fail even when `BouncerCaptchaGateSecret` is set. When `appsecEnabled` is true, it SHALL still validate AppSec URL, AppSec key, and AppSec HTTPS CA.

#### Scenario: Alone mode missing captcha keys
- **WHEN** mode is `alone`, failure action is `captcha`, provider is set, `BouncerCaptchaGateSecret` is set, and site/secret keys are empty
- **THEN** `ValidateParams` returns an error that names `BouncerCaptchaSiteKey` cannot be empty

#### Scenario: Alone mode invalid log level
- **WHEN** mode is `alone` and log level is not one of DEBUG/INFO/WARN/ERROR
- **THEN** `ValidateParams` returns an error

#### Scenario: Alone mode empty captcha path
- **WHEN** mode is `alone`, provider is set, site, secret, and gate resolve non-empty, and `BouncerCaptchaFilePath` is empty
- **THEN** `ValidateParams` returns `BouncerCaptchaFilePath: cannot be empty when BouncerCaptchaProvider is set`

### Requirement: Instance open versus subscribe validation
`ValidateParams` SHALL enforce the open-vs-subscribe matrix for each leg. When `bouncerEnabled` is false and the leg enable flag is false, a non-empty instance name, API key, or client certificate for that leg SHALL fail validation (E2). When `bouncerEnabled` is true, the leg enable flag is false, and the instance name is omitted after prepopulation rules, the bouncer SHALL NOT subscribe and validation SHALL succeed without treating the leg as open (E3). When a leg enable flag is true and neither API key nor client certificate can build that client, `ValidateParams` or subsequent `Open` failure SHALL fail `New` for that middleware.

#### Scenario: Leftover instance name with nothing enabled fails
- **WHEN** `bouncerEnabled` is false, `lapiEnabled` is false, and `lapiInstanceName` is `shared`
- **THEN** `ValidateParams` returns an error

#### Scenario: Bouncer with LAPI leg off and no name succeeds
- **WHEN** `bouncerEnabled` is true, `lapiEnabled` is false, AppSec is disabled, and `lapiInstanceName` is omitted
- **THEN** `ValidateParams` returns no error

### Requirement: crowdsecMode appsec value is rejected
`ValidateParams` SHALL reject `lapiMode: appsec` as an invalid mode value (E4). AppSec-only setups SHALL use `lapiEnabled: false` instead.

#### Scenario: Legacy appsec mode fails startup
- **WHEN** `lapiMode` is `appsec`
- **THEN** `ValidateParams` returns an error

### Requirement: ValidateParams test coverage for mode and helper gaps
The configuration package SHALL include unit tests covering: custom captcha provider missing fields; AppSec failure action `captcha` without provider; **LAPI disabled AppSec-only path (replaces appsec mode without LAPI key)**; alone mode captcha/template failures; `GetTemplate` error paths; `validateURL` bad host; `BouncerRemediationStatusCode` bounds 99/600; `LapiUpdateMaxFailure: -1` acceptance; **instance name E2/E3 cases**.

#### Scenario: AppSec captcha without provider rejected
- **WHEN** `bouncerAppsecFailureAction` is `captcha` and `bouncerCaptchaProvider` is empty
- **THEN** `ValidateParams` returns an error

### Requirement: Writable log path check does not retain its descriptor
When `LogFilePath` is non-empty, `ValidateParams` SHALL still reject an unwritable path. After a successful writability check it MUST NOT retain a file descriptor that exists only for that check. It MUST still perform the check even when a process-lifetime logger file is already open for the same path.

#### Scenario: Successful writable path leaves no check descriptor
- **WHEN** `ValidateParams` succeeds with a non-empty writable `LogFilePath` and no process-lifetime logger file is held for that path
- **THEN** the process has no open descriptor that names that path

#### Scenario: Unwritable path still fails
- **WHEN** `LogFilePath` is non-empty and not writable
- **THEN** `ValidateParams` returns an error

### Requirement: Redis password file resolved only when Redis is enabled
`ValidateParams` SHALL resolve `LapiRedisPassword` and `LapiRedisPasswordFile` only when `lapiRedisEnabled` is true. When `lapiRedisEnabled` is false, a missing, directory, or unreadable `lapiRedisPasswordFile` MUST NOT fail startup. When `lapiRedisEnabled` is true, a non-empty `lapiRedisPasswordFile` that is missing, a directory, or unreadable SHALL fail startup. An empty password with an empty file path SHALL still be accepted when Redis is enabled.

#### Scenario: Disabled Redis ignores a missing password file
- **WHEN** `lapiRedisEnabled` is false and `lapiRedisPasswordFile` names a path that does not exist
- **THEN** `ValidateParams` returns no error

#### Scenario: Disabled Redis ignores a stale password file
- **WHEN** `lapiRedisEnabled` is false and `lapiRedisPasswordFile` names a directory or an unreadable path
- **THEN** `ValidateParams` returns no error

#### Scenario: Enabled Redis still rejects a missing password file
- **WHEN** `lapiRedisEnabled` is true and `lapiRedisPasswordFile` names a path that does not exist
- **THEN** `ValidateParams` returns an error

#### Scenario: Enabled Redis accepts an empty password with no file
- **WHEN** `lapiRedisEnabled` is true, `lapiRedisPassword` is empty, and `lapiRedisPasswordFile` is empty
- **THEN** `ValidateParams` returns no error

### Requirement: Enabled AppSec requires a listener host
When `appsecEnabled` is true, `ValidateParams` SHALL reject an empty `appsecHost` and any AppSec URL that `http.NewRequest` accepts only because the host is missing. When `appsecEnabled` is false, `ValidateParams` MUST NOT fail solely because `appsecHost` is empty. Shared LAPI URL validation MUST keep accepting an empty host the same way it does today.

#### Scenario: Enabled AppSec with empty host is rejected
- **WHEN** `appsecEnabled` is true and `appsecHost` is empty
- **THEN** `ValidateParams` returns an error

#### Scenario: Disabled AppSec with empty host is accepted
- **WHEN** `appsecEnabled` is false, `appsecHost` is empty, and the rest of the config is valid
- **THEN** `ValidateParams` returns nil

### Requirement: Reject empty captcha site and secret after lookup
When `bouncerCaptchaProvider` is set, `ValidateParams` SHALL resolve `BouncerCaptchaSiteKey` and `BouncerCaptchaSecretKey` with the same file-then-field lookup used for `BouncerCaptchaGateSecret`. After a successful lookup it SHALL reject an empty trimmed string for each field independently, site first. The trigger is a non-empty provider, not a captcha failure action. Error text SHALL be `BouncerCaptchaSiteKey: cannot be empty when BouncerCaptchaProvider is set` and `BouncerCaptchaSecretKey: cannot be empty when BouncerCaptchaProvider is set`. A `ValidateParams` failure from this rule SHALL cause `New` to return a nil handler and that error without opening LAPI.

#### Scenario: Provider set with empty site and secret
- **WHEN** `bouncerCaptchaProvider` is set, `BouncerCaptchaGateSecret` is set, and both site and secret resolve empty
- **THEN** `ValidateParams` returns `BouncerCaptchaSiteKey: cannot be empty when BouncerCaptchaProvider is set`

#### Scenario: Only site empty
- **WHEN** `bouncerCaptchaProvider` is set, secret is non-empty, and site resolves empty
- **THEN** `ValidateParams` returns `BouncerCaptchaSiteKey: cannot be empty when BouncerCaptchaProvider is set`

#### Scenario: Only secret empty
- **WHEN** `bouncerCaptchaProvider` is set, site is non-empty, and secret resolves empty
- **THEN** `ValidateParams` returns `BouncerCaptchaSecretKey: cannot be empty when BouncerCaptchaProvider is set`

#### Scenario: Whitespace-only site is empty
- **WHEN** `bouncerCaptchaProvider` is set and site is only whitespace
- **THEN** `ValidateParams` returns `BouncerCaptchaSiteKey: cannot be empty when BouncerCaptchaProvider is set`

#### Scenario: Default ban action still rejects empty keys
- **WHEN** `bouncerCaptchaProvider` is set, failure actions are the default `ban`, and site/secret resolve empty
- **THEN** `ValidateParams` returns an error that names the empty site key

#### Scenario: New returns no handler
- **WHEN** `New` is called with `bouncerCaptchaProvider` set, `BouncerCaptchaGateSecret` set, and empty site key
- **THEN** `New` returns a nil handler and an error
- **AND** it does not open LAPI

### Requirement: AppSec URL key and HTTPS CA validated only when enabled
When `appsecEnabled` is true, `ValidateParams` SHALL validate AppSec URL (effective scheme), AppSec key file-then-field lookup, and AppSec HTTPS CA PEM (explicit `https` scheme and insecure-verify false) in every `lapiMode`. When `appsecEnabled` is false, it MUST NOT validate AppSec host, URL, key, or CA, even if leftover fields are set. Alone mode SHALL still skip LAPI URL, LAPI key, and LAPI TLS after CAPI machine id and password. Live, stream, and none modes SHALL still validate LAPI. An empty AppSec key after a successful lookup SHALL still pass.

#### Scenario: Alone AppSec on with invalid CA
- **WHEN** mode is `alone`, CAPI machine id and password are set, `appsecEnabled` is true, `appsecScheme` is `https`, and AppSec CA PEM is garbage
- **THEN** `ValidateParams` returns an error

#### Scenario: Alone AppSec on with missing key file
- **WHEN** mode is `alone`, CAPI machine id and password are set, `appsecEnabled` is true, and `appsecKeyFile` names a missing path
- **THEN** `ValidateParams` returns an error that names `AppsecKey` and an invalid path

#### Scenario: Alone AppSec off leftover CA and key file
- **WHEN** mode is `alone`, CAPI machine id and password are set, `appsecEnabled` is false, AppSec CA PEM is garbage, and `appsecKeyFile` names a missing path
- **THEN** `ValidateParams` returns no error

#### Scenario: Live AppSec off leftover CA and key file
- **WHEN** mode is `live` or `stream`, LAPI is valid, `appsecEnabled` is false, AppSec CA PEM is garbage, and `appsecKeyFile` names a missing path
- **THEN** `ValidateParams` returns no error

#### Scenario: Live AppSec on with invalid CA
- **WHEN** mode is `live` or `stream`, LAPI is valid, `appsecEnabled` is true, `appsecScheme` is `https`, and AppSec CA PEM is garbage
- **THEN** `ValidateParams` returns an error

#### Scenario: Live AppSec on with missing key file
- **WHEN** mode is `live` or `stream`, LAPI is valid, `appsecEnabled` is true, and `appsecKeyFile` names a missing path
- **THEN** `ValidateParams` returns an error that names `AppsecKey` and an invalid path

### Requirement: Provider set requires a loadable captcha template
When `bouncerCaptchaProvider` is set, `ValidateParams` SHALL reject an empty `BouncerCaptchaFilePath` and SHALL fail when `GetTemplate` fails for that path. The trigger is a non-empty provider, the same as site, secret, and gate. Error text for the empty path SHALL be `BouncerCaptchaFilePath: cannot be empty when BouncerCaptchaProvider is set`. A `GetTemplate` failure SHALL be returned as that error. Ban template validation SHALL stay "when path is set". `Client.New` SHALL return the `GetTemplate` error and MUST NOT discard it. The plugin MUST NOT invent a bundled default captcha template. A `ValidateParams` failure from this rule SHALL cause `New` to return a nil handler and that error without opening LAPI.

#### Scenario: Provider set with empty captcha path
- **WHEN** `bouncerCaptchaProvider` is set, site, secret, and gate resolve non-empty, and `BouncerCaptchaFilePath` is empty
- **THEN** `ValidateParams` returns `BouncerCaptchaFilePath: cannot be empty when BouncerCaptchaProvider is set`

#### Scenario: Provider set with unreadable captcha path
- **WHEN** `bouncerCaptchaProvider` is set and `BouncerCaptchaFilePath` names a missing or unparseable file
- **THEN** `ValidateParams` returns a `GetTemplate` error

#### Scenario: Empty ban path still accepted
- **WHEN** `bouncerCaptchaProvider` is set, captcha path is loadable, and `BouncerBanFilePath` is empty
- **THEN** `ValidateParams` returns no error from the ban template

#### Scenario: Client.New returns GetTemplate error
- **WHEN** `Client.New` is called with a non-empty provider and an empty or unreadable captcha template path
- **THEN** `Client.New` returns the `GetTemplate` error
- **AND** it does not return nil with a discarded error

#### Scenario: New returns no handler on empty captcha path
- **WHEN** `New` is called with `bouncerCaptchaProvider` set, site, secret, and gate set, and empty `BouncerCaptchaFilePath`
- **THEN** `New` returns a nil handler and an error
- **AND** it does not open LAPI

### Requirement: CaptchaCustomValidateBody accepted tokens
`ValidateParams` SHALL trim `BouncerCaptchaCustomValidateBody` and accept only `""`, `form`, and `json` (exact lowercase). Any other token SHALL fail for any provider. `json` SHALL fail when `bouncerCaptchaProvider` is not `custom`. Empty or `form` on a built-in provider SHALL pass and be ignored. Error text SHALL name `BouncerCaptchaCustomValidateBody`. Unknown-token errors SHALL be `BouncerCaptchaCustomValidateBody: must be empty, form, or json`. Built-in-plus-`json` errors SHALL be `BouncerCaptchaCustomValidateBody: json is only valid when BouncerCaptchaProvider is custom`.

#### Scenario: Custom json accepted
- **WHEN** the provider is `custom`, the four required custom strings are set, and `BouncerCaptchaCustomValidateBody` is `json`
- **THEN** `ValidateParams` returns no error

#### Scenario: Custom form or omit accepted
- **WHEN** the provider is `custom`, the four required custom strings are set, and `BouncerCaptchaCustomValidateBody` is empty or `form`
- **THEN** `ValidateParams` returns no error

#### Scenario: Built-in json rejected
- **WHEN** the provider is hcaptcha, recaptcha, or turnstile and `BouncerCaptchaCustomValidateBody` is `json`
- **THEN** `ValidateParams` returns `BouncerCaptchaCustomValidateBody: json is only valid when BouncerCaptchaProvider is custom`

#### Scenario: Unknown token rejected
- **WHEN** `BouncerCaptchaCustomValidateBody` is `JSON`, `Form`, or any other token that is not empty, `form`, or `json` after trim
- **THEN** `ValidateParams` returns `BouncerCaptchaCustomValidateBody: must be empty, form, or json`

#### Scenario: Built-in form or omit accepted
- **WHEN** the provider is a built-in and `BouncerCaptchaCustomValidateBody` is empty or `form`
- **THEN** `ValidateParams` returns no error

#### Scenario: Whitespace-padded json is json
- **WHEN** the provider is `custom`, the four required custom strings are set, and `BouncerCaptchaCustomValidateBody` is ` json `
- **THEN** `ValidateParams` returns no error

### Requirement: Public Config keys use domain prefixes
`Config` SHALL expose flat public JSON keys whose first syllable is the piece that reads them (`lapi`, `appsec`, `bouncer`). Logging keys (`logLevel`, `logFormat`, `logFilePath`) and `reclaimGraceSeconds` SHALL stay unprefixed. The plugin MUST NOT accept old `crowdsec*` keys or unprefixed router knobs as aliases, and MUST NOT nest those maps. `GetVariable` lookup strings SHALL be the new Go field names (`LapiKey`, `LapiTLSClientCertificate`, `AppsecKey`, `BouncerCaptchaSiteKey`). TLS prefix helpers SHALL be `Lapi` / `Appsec` plus `TLSCertificateAuthority`, `TLSClientCertificate`, and `TLSClientKey`. Validation errors SHALL name the new Go field.

#### Scenario: Old crowdsec key is ignored
- **WHEN** operator YAML sets only `crowdsecLapiHost` and omits `lapiHost`
- **THEN** Traefik decode leaves `LapiHost` at the CreateConfig default
- **AND** the old key is not a field on `Config`

#### Scenario: GetVariable uses the new field name
- **WHEN** `GetVariable` is called with `LapiKey` and `LapiKeyFile` names a readable file
- **THEN** the lookup returns that file’s trimmed contents
- **AND** a call with `CrowdsecLapiKey` does not resolve `LapiKeyFile`

### Requirement: Independent HTTP timeout knobs
`Config` SHALL expose `LapiHTTPTimeoutSeconds` (`lapiHttpTimeoutSeconds`), `AppsecHTTPTimeoutSeconds` (`appsecHttpTimeoutSeconds`), and `BouncerCaptchaSiteverifyHTTPTimeoutSeconds` (`bouncerCaptchaSiteverifyHttpTimeoutSeconds`). `CreateConfig` and `configuration.New` SHALL default each to 10. `ValidateParams` SHALL reject any of those knobs less than 1 (`cannot be less than 1`). `Config` MUST NOT expose `HTTPTimeoutSeconds`, `httpTimeoutSeconds`, or `EffectiveHTTPTimeoutSeconds`. Setting one timeout MUST NOT move the others. An omitted AppSec scheme or key MAY still copy from LAPI when AppSec is owned; the AppSec timeout MUST NOT copy.

#### Scenario: Defaults are ten
- **WHEN** the operator omits all three timeout keys
- **THEN** `CreateConfig` leaves each knob at 10
- **AND** `ValidateParams` returns no error

#### Scenario: Zero is invalid
- **WHEN** `lapiHttpTimeoutSeconds` is 0
- **THEN** `ValidateParams` returns an error that names `LapiHTTPTimeoutSeconds` and `cannot be less than 1`

#### Scenario: One knob does not move the others
- **WHEN** `lapiHttpTimeoutSeconds` is 2 and `appsecHttpTimeoutSeconds` is omitted
- **THEN** LAPI timeout is 2 and AppSec timeout stays 10
