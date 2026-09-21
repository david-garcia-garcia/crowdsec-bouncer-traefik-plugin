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
When `appsecEnabled` is true, `appsecScheme` is explicitly set to `https`, and `appsecTlsInsecureVerify` is false, `ValidateParams` SHALL parse `appsecTlsCa` PEM when provided, rejecting invalid PEM the same way LAPI CA is rejected today.

#### Scenario: Invalid AppSec CA with LAPI HTTP
- **WHEN** `appsecEnabled` is true, `lapiScheme` is `http`, `appsecScheme` is `https`, and AppSec CA PEM is garbage
- **THEN** `ValidateParams` returns an error

### Requirement: Alone mode validates captcha templates and logging
In `lapiMode: alone`, `ValidateParams` SHALL still validate captcha site/secret keys when a captcha provider is configured, the captcha template when a provider is set (empty `BouncerCaptchaFile` or a `GetTemplate` failure SHALL fail), the ban template when that path is set, and log level / writable log file path. It MAY skip LAPI URL, LAPI key, and LAPI TLS checks after CAPI credential validation. Empty site or secret after file-then-field lookup SHALL fail even when `BouncerCaptchaGateSecret` is set. When `appsecEnabled` is true, it SHALL still validate AppSec URL, AppSec key, and AppSec HTTPS CA.

#### Scenario: Alone mode missing captcha keys
- **WHEN** mode is `alone`, failure action is `captcha`, provider is set, `BouncerCaptchaGateSecret` is set, and site/secret keys are empty
- **THEN** `ValidateParams` returns an error that names `BouncerCaptchaSiteKey` cannot be empty

#### Scenario: Alone mode invalid log level
- **WHEN** mode is `alone` and log level is not one of DEBUG/INFO/WARN/ERROR
- **THEN** `ValidateParams` returns an error

#### Scenario: Alone mode empty captcha path
- **WHEN** mode is `alone`, provider is set, site, secret, and gate resolve non-empty, and `BouncerCaptchaFile` is empty
- **THEN** `ValidateParams` returns `BouncerCaptchaFile: cannot be empty when BouncerCaptchaProvider is set`

### Requirement: Enable flags and instance names
`ValidateParams` SHALL accept `lapiEnabled` (default true) and `appsecEnabled` (default false). When `lapiEnabled` is true and the middleware has LAPI secrets (key, client cert, or alone CAPI), it SHALL accept Open. When `lapiEnabled` is true, `lapiInstance` is non-empty, and there are no LAPI secrets, it SHALL accept subscribe. When `lapiEnabled` is true with no secrets and empty `lapiInstance`, it SHALL fail. When `lapiEnabled` is false, leftover LAPI secrets or a non-empty `lapiInstance` SHALL fail. The same four cases apply to AppSec with AppSec key as the secret. `bouncerHold` true together with `bouncerEnabled` true SHALL fail. `lapiMode` SHALL be `live`, `stream`, `none`, or `alone` when this middleware Opens LAPI.

#### Scenario: Subscribe without a LAPI key
- **WHEN** `lapiEnabled` is true, `lapiInstance` is `shared`, and `lapiKey` is empty
- **THEN** `ValidateParams` returns no error

#### Scenario: Own LAPI missing key fails
- **WHEN** `lapiEnabled` is true, `lapiInstance` is empty, and there are no LAPI secrets
- **THEN** `ValidateParams` returns an error

#### Scenario: Disabled LAPI with leftover key fails
- **WHEN** `lapiEnabled` is false and `lapiKey` is non-empty
- **THEN** `ValidateParams` returns an error

### Requirement: ValidateParams test coverage for mode and helper gaps
The configuration package SHALL include unit tests covering: custom captcha provider missing fields; AppSec failure action `captcha` without provider; AppSec-only without LAPI key; alone mode captcha/template failures; `GetTemplate` error paths; `validateURL` bad host; `BouncerRemediationStatusCode` bounds 99/600; `LapiUpdateMaxFailure: -1` acceptance.

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
When `appsecEnabled` is true, `ValidateParams` SHALL validate AppSec URL (effective scheme), AppSec key file-then-field lookup, and AppSec HTTPS CA PEM (explicit `https` scheme and insecure-verify false) in every `lapiMode`. When `appsecEnabled` is false, it MUST NOT validate AppSec host, URL, key, or CA, even if leftover fields are set. Alone mode SHALL still skip LAPI URL, LAPI key, and LAPI TLS after CAPI machine id and password. LAPI URL, key, and TLS SHALL run only when this middleware Opens LAPI. An empty AppSec key after a successful lookup SHALL still pass.

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

### Requirement: HTTP timeout inherit knobs
`Config` SHALL keep public `HTTPTimeoutSeconds` (JSON `httpTimeoutSeconds`, default 10). It SHALL add `LapiHttpTimeoutSeconds` (`lapiHttpTimeoutSeconds`), `AppsecHttpTimeoutSeconds` (`appsecHttpTimeoutSeconds`), and `BouncerCaptchaHttpTimeoutSeconds` (`bouncerCaptchaHttpTimeoutSeconds`). `CreateConfig` and `configuration.New` SHALL leave those three knobs at 0. `Config` SHALL expose one method `EffectiveHTTPTimeoutSeconds(override int64) int64` that returns `HTTPTimeoutSeconds` when `override == 0` and otherwise returns `override`. The method MUST NOT coerce a negative override to the shared default. `ValidateParams` SHALL reject a new knob less than 0 (`cannot be less than 0`) and SHALL keep rejecting `HTTPTimeoutSeconds` less than 1 (`cannot be less than 1`).

#### Scenario: Omit and zero inherit the shared default
- **WHEN** `HTTPTimeoutSeconds` is 10 and a new knob is 0 or omitted
- **THEN** `EffectiveHTTPTimeoutSeconds` for that knob returns 10
- **AND** `ValidateParams` returns no error for those zeros

#### Scenario: Positive override wins
- **WHEN** `HTTPTimeoutSeconds` is 10 and `AppsecHttpTimeoutSeconds` is 1
- **THEN** `EffectiveHTTPTimeoutSeconds(AppsecHttpTimeoutSeconds)` returns 1

#### Scenario: Negative inherit knob is invalid
- **WHEN** `LapiHttpTimeoutSeconds` is -1
- **THEN** `ValidateParams` returns an error that names `LapiHttpTimeoutSeconds` and `cannot be less than 0`

#### Scenario: Shared timeout below one stays invalid
- **WHEN** `HTTPTimeoutSeconds` is 0
- **THEN** `ValidateParams` returns an error that names `HTTPTimeoutSeconds` and `cannot be less than 1`

### Requirement: Provider set requires a loadable captcha template

When `bouncerCaptchaProvider` is set, `ValidateParams` SHALL reject an empty `BouncerCaptchaFile` and SHALL fail when `GetTemplate` fails for that path. The trigger is a non-empty provider, the same as site, secret, and gate. Error text for the empty path SHALL be `BouncerCaptchaFile: cannot be empty when BouncerCaptchaProvider is set`. A `GetTemplate` failure SHALL be returned as that error. Ban template validation SHALL stay "when path is set". `Client.New` SHALL return the `GetTemplate` error and MUST NOT discard it. The plugin MUST NOT invent a bundled default captcha template. A `ValidateParams` failure from this rule SHALL cause `New` to return a nil handler and that error without opening LAPI.

#### Scenario: Provider set with empty captcha path

- **WHEN** `bouncerCaptchaProvider` is set, site, secret, and gate resolve non-empty, and `BouncerCaptchaFile` is empty
- **THEN** `ValidateParams` returns `BouncerCaptchaFile: cannot be empty when BouncerCaptchaProvider is set`

#### Scenario: Provider set with unreadable captcha path

- **WHEN** `bouncerCaptchaProvider` is set and `BouncerCaptchaFile` names a missing or unparseable file
- **THEN** `ValidateParams` returns a `GetTemplate` error

#### Scenario: Empty ban path still accepted

- **WHEN** `bouncerCaptchaProvider` is set, captcha path is loadable, and `BouncerBanFile` is empty
- **THEN** `ValidateParams` returns no error from the ban template

#### Scenario: Client.New returns GetTemplate error

- **WHEN** `Client.New` is called with a non-empty provider and an empty or unreadable captcha template path
- **THEN** `Client.New` returns the `GetTemplate` error
- **AND** it does not return nil with a discarded error

#### Scenario: New returns no handler on empty captcha path

- **WHEN** `New` is called with `bouncerCaptchaProvider` set, site, secret, and gate set, and empty `BouncerCaptchaFile`
- **THEN** `New` returns a nil handler and an error
- **AND** it does not open LAPI


### Requirement: BouncerCaptchaCustomValidateBody accepted tokens
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

