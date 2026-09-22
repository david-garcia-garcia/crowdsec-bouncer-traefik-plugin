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
In `crowdsecMode: alone`, `ValidateParams` SHALL still validate captcha site/secret keys when a captcha provider is configured, the captcha template when a provider is set (empty `CaptchaFilePath` or a `GetTemplate` failure SHALL fail), the ban template when that path is set, and log level / writable log file path. It MAY skip LAPI URL, LAPI key, and LAPI TLS checks after CAPI credential validation. Empty site or secret after file-then-field lookup SHALL fail even when `CaptchaGateSecret` is set. When `crowdsecAppsecEnabled` is true, it SHALL still validate AppSec URL, AppSec key, and AppSec HTTPS CA.

#### Scenario: Alone mode missing captcha keys
- **WHEN** mode is `alone`, failure action is `captcha`, provider is set, `CaptchaGateSecret` is set, and site/secret keys are empty
- **THEN** `ValidateParams` returns an error that names `CaptchaSiteKey` cannot be empty

#### Scenario: Alone mode invalid log level
- **WHEN** mode is `alone` and log level is not one of DEBUG/INFO/WARN/ERROR
- **THEN** `ValidateParams` returns an error

#### Scenario: Alone mode empty captcha path
- **WHEN** mode is `alone`, provider is set, site, secret, and gate resolve non-empty, and `CaptchaFilePath` is empty
- **THEN** `ValidateParams` returns `CaptchaFilePath: cannot be empty when CaptchaProvider is set`

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

### Requirement: ValidateParams test coverage for mode and helper gaps
The configuration package SHALL include unit tests covering: custom captcha provider missing fields; AppSec failure action `captcha` without provider; **LAPI disabled AppSec-only path (replaces appsec mode without LAPI key)**; alone mode captcha/template failures; `GetTemplate` error paths; `validateURL` bad host; `RemediationStatusCode` bounds 99/600; `UpdateMaxFailure: -1` acceptance; **instance name E2/E3 cases**.

#### Scenario: AppSec captcha without provider rejected
- **WHEN** `crowdsecAppsecFailureAction` is `captcha` and `captchaProvider` is empty
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
When `crowdsecAppsecEnabled` is true, `ValidateParams` SHALL validate AppSec URL (effective scheme), AppSec key file-then-field lookup, and AppSec HTTPS CA PEM (explicit `https` scheme and insecure-verify false) in every `crowdsecMode`. When `crowdsecAppsecEnabled` is false, it MUST NOT validate AppSec host, URL, key, or CA, even if leftover fields are set. Alone mode SHALL still skip LAPI URL, LAPI key, and LAPI TLS after CAPI machine id and password. Live, stream, and none modes SHALL still validate LAPI. An empty AppSec key after a successful lookup SHALL still pass.

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

### Requirement: HTTP timeout inherit knobs
`Config` SHALL keep public `HTTPTimeoutSeconds` (JSON `httpTimeoutSeconds`, default 10). It SHALL add `CrowdsecLapiHTTPTimeoutSeconds` (`crowdsecLapiHttpTimeoutSeconds`), `CrowdsecAppsecHTTPTimeoutSeconds` (`crowdsecAppsecHttpTimeoutSeconds`), and `CaptchaSiteverifyHTTPTimeoutSeconds` (`captchaSiteverifyHttpTimeoutSeconds`). `CreateConfig` and `configuration.New` SHALL leave those three knobs at 0. `Config` SHALL expose one method `EffectiveHTTPTimeoutSeconds(override int64) int64` that returns `HTTPTimeoutSeconds` when `override == 0` and otherwise returns `override`. The method MUST NOT coerce a negative override to the shared default. `ValidateParams` SHALL reject a new knob less than 0 (`cannot be less than 0`) and SHALL keep rejecting `HTTPTimeoutSeconds` less than 1 (`cannot be less than 1`).

#### Scenario: Omit and zero inherit the shared default
- **WHEN** `HTTPTimeoutSeconds` is 10 and a new knob is 0 or omitted
- **THEN** `EffectiveHTTPTimeoutSeconds` for that knob returns 10
- **AND** `ValidateParams` returns no error for those zeros

#### Scenario: Positive override wins
- **WHEN** `HTTPTimeoutSeconds` is 10 and `CrowdsecAppsecHTTPTimeoutSeconds` is 1
- **THEN** `EffectiveHTTPTimeoutSeconds(CrowdsecAppsecHTTPTimeoutSeconds)` returns 1

#### Scenario: Negative inherit knob is invalid
- **WHEN** `CrowdsecLapiHTTPTimeoutSeconds` is -1
- **THEN** `ValidateParams` returns an error that names `CrowdsecLapiHTTPTimeoutSeconds` and `cannot be less than 0`

#### Scenario: Shared timeout below one stays invalid
- **WHEN** `HTTPTimeoutSeconds` is 0
- **THEN** `ValidateParams` returns an error that names `HTTPTimeoutSeconds` and `cannot be less than 1`

### Requirement: Provider set requires a loadable captcha template

When `captchaProvider` is set, `ValidateParams` SHALL reject an empty `CaptchaFilePath` and SHALL fail when `GetTemplate` fails for that path. The trigger is a non-empty provider, the same as site, secret, and gate. Error text for the empty path SHALL be `CaptchaFilePath: cannot be empty when CaptchaProvider is set`. A `GetTemplate` failure SHALL be returned as that error. Ban template validation SHALL stay "when path is set". `Client.New` SHALL return the `GetTemplate` error and MUST NOT discard it. The plugin MUST NOT invent a bundled default captcha template. A `ValidateParams` failure from this rule SHALL cause `New` to return a nil handler and that error without opening LAPI.

#### Scenario: Provider set with empty captcha path

- **WHEN** `captchaProvider` is set, site, secret, and gate resolve non-empty, and `CaptchaFilePath` is empty
- **THEN** `ValidateParams` returns `CaptchaFilePath: cannot be empty when CaptchaProvider is set`

#### Scenario: Provider set with unreadable captcha path

- **WHEN** `captchaProvider` is set and `CaptchaFilePath` names a missing or unparseable file
- **THEN** `ValidateParams` returns a `GetTemplate` error

#### Scenario: Empty ban path still accepted

- **WHEN** `captchaProvider` is set, captcha path is loadable, and `BanFilePath` is empty
- **THEN** `ValidateParams` returns no error from the ban template

#### Scenario: Client.New returns GetTemplate error

- **WHEN** `Client.New` is called with a non-empty provider and an empty or unreadable captcha template path
- **THEN** `Client.New` returns the `GetTemplate` error
- **AND** it does not return nil with a discarded error

#### Scenario: New returns no handler on empty captcha path

- **WHEN** `New` is called with `captchaProvider` set, site, secret, and gate set, and empty `CaptchaFilePath`
- **THEN** `New` returns a nil handler and an error
- **AND** it does not open LAPI


### Requirement: CaptchaCustomValidateBody accepted tokens
`ValidateParams` SHALL trim `CaptchaCustomValidateBody` and accept only `""`, `form`, and `json` (exact lowercase). Any other token SHALL fail for any provider. `json` SHALL fail when `captchaProvider` is not `custom`. Empty or `form` on a built-in provider SHALL pass and be ignored. Error text SHALL name `CaptchaCustomValidateBody`. Unknown-token errors SHALL be `CaptchaCustomValidateBody: must be empty, form, or json`. Built-in-plus-`json` errors SHALL be `CaptchaCustomValidateBody: json is only valid when CaptchaProvider is custom`.

#### Scenario: Custom json accepted
- **WHEN** the provider is `custom`, the four required custom strings are set, and `CaptchaCustomValidateBody` is `json`
- **THEN** `ValidateParams` returns no error

#### Scenario: Custom form or omit accepted
- **WHEN** the provider is `custom`, the four required custom strings are set, and `CaptchaCustomValidateBody` is empty or `form`
- **THEN** `ValidateParams` returns no error

#### Scenario: Built-in json rejected
- **WHEN** the provider is hcaptcha, recaptcha, or turnstile and `CaptchaCustomValidateBody` is `json`
- **THEN** `ValidateParams` returns `CaptchaCustomValidateBody: json is only valid when CaptchaProvider is custom`

#### Scenario: Unknown token rejected
- **WHEN** `CaptchaCustomValidateBody` is `JSON`, `Form`, or any other token that is not empty, `form`, or `json` after trim
- **THEN** `ValidateParams` returns `CaptchaCustomValidateBody: must be empty, form, or json`

#### Scenario: Built-in form or omit accepted
- **WHEN** the provider is a built-in and `CaptchaCustomValidateBody` is empty or `form`
- **THEN** `ValidateParams` returns no error

#### Scenario: Whitespace-padded json is json
- **WHEN** the provider is `custom`, the four required custom strings are set, and `CaptchaCustomValidateBody` is ` json `
- **THEN** `ValidateParams` returns no error

