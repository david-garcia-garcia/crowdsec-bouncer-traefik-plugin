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
In `lapiMode: alone`, `ValidateParams` SHALL still validate captcha site/secret keys when `captchaEnabled` is true, the captcha template when `captchaEnabled` is true (empty `CaptchaFilePath` or a `GetTemplate` failure SHALL fail), the ban template when that path is set, and log level / writable log file path. It MAY skip LAPI URL, LAPI key, and LAPI TLS checks after CAPI credential validation. Empty site after file-then-field lookup SHALL fail even when `CaptchaGateSecret` is set. Empty secret after lookup SHALL fail when the provider is not `recaptcha-enterprise`, even when `CaptchaGateSecret` is set. When the provider is `recaptcha-enterprise`, empty secret SHALL pass. When `appsecEnabled` is true, it SHALL still validate AppSec URL, AppSec key, and AppSec HTTPS CA.

#### Scenario: Alone mode missing captcha keys
- **WHEN** mode is `alone`, `captchaEnabled` is true, failure action is `captcha`, provider is set, `CaptchaGateSecret` is set, and site/secret keys are empty
- **THEN** `ValidateParams` returns an error that names `CaptchaSiteKey` cannot be empty

#### Scenario: Alone mode invalid log level
- **WHEN** mode is `alone` and log level is not one of DEBUG/INFO/WARN/ERROR
- **THEN** `ValidateParams` returns an error

#### Scenario: Alone mode empty captcha path
- **WHEN** mode is `alone`, `captchaEnabled` is true, provider is set, site, secret, and gate resolve non-empty, and `CaptchaFilePath` is empty
- **THEN** `ValidateParams` returns `CaptchaFilePath: cannot be empty when CaptchaProvider is set`

### Requirement: Instance open versus subscribe validation
`ValidateParams` SHALL enforce the open-vs-subscribe matrix for each leg (LAPI, AppSec, and captcha). When `bouncerEnabled` is false and the leg enable flag is false, a non-empty instance name, API key, or client certificate for that leg SHALL fail validation (E2). Captcha E2 is a leftover `captchaInstanceName` (not leftover owner-read `captcha*` keys). When `bouncerEnabled` is true, the leg enable flag is false, and the instance name is omitted after prepopulation rules, the bouncer SHALL NOT subscribe and validation SHALL succeed without treating the leg as open (E3). When a LAPI or AppSec enable flag is true and neither API key nor client certificate can build that client, `ValidateParams` or subsequent `Open` failure SHALL fail `New` for that middleware. When `captchaEnabled` is true, owner-style captcha checks SHALL fail `New` if provider, keys, gate secret, or template cannot build the client. For `recaptcha-enterprise`, those keys are the site key and the enterprise knobs, not `CaptchaSecretKey`.

#### Scenario: Leftover instance name with nothing enabled fails
- **WHEN** `bouncerEnabled` is false, `lapiEnabled` is false, and `lapiInstanceName` is `shared`
- **THEN** `ValidateParams` returns an error

#### Scenario: Bouncer with LAPI leg off and no name succeeds
- **WHEN** `bouncerEnabled` is true, `lapiEnabled` is false, AppSec is disabled, and `lapiInstanceName` is omitted
- **THEN** `ValidateParams` returns no error

#### Scenario: Leftover captcha instance name with nothing enabled fails
- **WHEN** `bouncerEnabled` is false, `captchaEnabled` is false, and `captchaInstanceName` is `shared`
- **THEN** `ValidateParams` returns an error

### Requirement: crowdsecMode appsec value is rejected
`ValidateParams` SHALL reject `lapiMode: appsec` as an invalid mode value (E4). AppSec-only setups SHALL use `lapiEnabled: false` instead.

#### Scenario: Legacy appsec mode fails startup
- **WHEN** `lapiMode` is `appsec`
- **THEN** `ValidateParams` returns an error

### Requirement: ValidateParams test coverage for mode and helper gaps
The configuration package SHALL include unit tests covering: custom captcha provider missing fields; AppSec failure action `captcha` without a captcha instance name; **LAPI disabled AppSec-only path (replaces appsec mode without LAPI key)**; alone mode captcha/template failures; `GetTemplate` error paths; `validateURL` bad host; `BouncerRemediationStatusCode` bounds 99/600; `LapiUpdateMaxFailure: -1` acceptance; **instance name E2/E3 cases including captcha**.

#### Scenario: AppSec captcha without instance name rejected
- **WHEN** `bouncerAppsecFailureAction` is `captcha` and `captchaInstanceName` is empty after owner-fill rules
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
When `captchaEnabled` is true, `ValidateParams` SHALL resolve `CaptchaSiteKey` and `CaptchaSecretKey` with the same file-then-field lookup used for `CaptchaGateSecret`. After a successful lookup it SHALL reject an empty trimmed string for the site key. It SHALL reject an empty trimmed secret when `captchaProvider` is not `recaptcha-enterprise`. When `captchaProvider` is `recaptcha-enterprise`, an empty secret SHALL pass. Site is still checked first. The trigger is `captchaEnabled`, not a leftover provider on a subscriber and not a captcha failure action. Error text SHALL be `CaptchaSiteKey: cannot be empty when CaptchaProvider is set` and `CaptchaSecretKey: cannot be empty when CaptchaProvider is set`. A `ValidateParams` failure from this rule SHALL cause `New` to return a nil handler and that error without opening LAPI.

#### Scenario: Provider set with empty site and secret
- **WHEN** `captchaEnabled` is true, `captchaProvider` is set, `CaptchaGateSecret` is set, and both site and secret resolve empty
- **THEN** `ValidateParams` returns `CaptchaSiteKey: cannot be empty when CaptchaProvider is set`

#### Scenario: Only site empty
- **WHEN** `captchaEnabled` is true, `captchaProvider` is set, secret is non-empty, and site resolves empty
- **THEN** `ValidateParams` returns `CaptchaSiteKey: cannot be empty when CaptchaProvider is set`

#### Scenario: Only secret empty
- **WHEN** `captchaEnabled` is true, `captchaProvider` is `hcaptcha`, `recaptcha`, `turnstile`, `custom`, or `eucaptcha`, site is non-empty, and secret resolves empty
- **THEN** `ValidateParams` returns `CaptchaSecretKey: cannot be empty when CaptchaProvider is set`

#### Scenario: Enterprise empty secret is accepted
- **WHEN** `captchaEnabled` is true, `captchaProvider` is `recaptcha-enterprise`, site is non-empty, gate is set, required enterprise knobs are set, and secret resolves empty
- **THEN** `ValidateParams` returns no error from the secret

#### Scenario: Whitespace-only site is empty
- **WHEN** `captchaEnabled` is true, `captchaProvider` is set, and site is only whitespace
- **THEN** `ValidateParams` returns `CaptchaSiteKey: cannot be empty when CaptchaProvider is set`

#### Scenario: Default ban action still rejects empty keys
- **WHEN** `captchaEnabled` is true, `captchaProvider` is set, failure actions are the default `ban`, and site/secret resolve empty
- **THEN** `ValidateParams` returns an error that names the empty site key

#### Scenario: New returns no handler
- **WHEN** `New` is called with `captchaEnabled` true, `captchaProvider` set, `CaptchaGateSecret` set, and empty site key
- **THEN** `New` returns a nil handler and an error
- **AND** it does not open LAPI

#### Scenario: Subscriber leftover provider does not require keys
- **WHEN** `captchaEnabled` is false and leftover `captchaProvider` is set with empty site and secret
- **THEN** `ValidateParams` does not fail from this rule

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
When `captchaEnabled` is true, `ValidateParams` SHALL reject an empty `CaptchaFilePath` and SHALL fail when `GetTemplate` fails for that path. The trigger is `captchaEnabled`, the same as site, secret, and gate. Error text for the empty path SHALL be `CaptchaFilePath: cannot be empty when CaptchaProvider is set`. A `GetTemplate` failure SHALL be returned as that error. Ban template validation SHALL stay "when path is set". `Client.New` SHALL return the `GetTemplate` error and MUST NOT discard it. The plugin MUST NOT invent a bundled default captcha template. A `ValidateParams` failure from this rule SHALL cause `New` to return a nil handler and that error without opening LAPI.

#### Scenario: Provider set with empty captcha path
- **WHEN** `captchaEnabled` is true, `captchaProvider` is set, site, secret, and gate resolve non-empty, and `CaptchaFilePath` is empty
- **THEN** `ValidateParams` returns `CaptchaFilePath: cannot be empty when CaptchaProvider is set`

#### Scenario: Provider set with unreadable captcha path
- **WHEN** `captchaEnabled` is true, `captchaProvider` is set, and `CaptchaFilePath` names a missing or unparseable file
- **THEN** `ValidateParams` returns a `GetTemplate` error

#### Scenario: Empty ban path still accepted
- **WHEN** `captchaEnabled` is true, `captchaProvider` is set, captcha path is loadable, and `BouncerBanFilePath` is empty
- **THEN** `ValidateParams` returns no error from the ban template

#### Scenario: Client.New returns GetTemplate error
- **WHEN** `Client.New` is called with a non-empty provider and an empty or unreadable captcha template path
- **THEN** `Client.New` returns the `GetTemplate` error
- **AND** it does not return nil with a discarded error

#### Scenario: New returns no handler on empty captcha path
- **WHEN** `New` is called with `captchaEnabled` true, `captchaProvider` set, site, secret, and gate set, and empty `CaptchaFilePath`
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

### Requirement: Public Config keys use domain prefixes
`Config` SHALL expose flat public JSON keys whose first syllable is the piece that reads them (`lapi`, `appsec`, `bouncer`, `captcha`). Own-axis captcha keys SHALL be `captchaEnabled` and `captchaInstanceName`. Owner-read captcha settings SHALL be `captcha*` (`Captcha*` Go fields). The plugin MUST NOT accept old `bouncerCaptcha*` keys as aliases. Logging keys (`logLevel`, `logFormat`, `logFilePath`) and `reclaimGraceSeconds` SHALL stay unprefixed. The plugin MUST NOT accept old `crowdsec*` keys or unprefixed router knobs as aliases, and MUST NOT nest those maps. `GetVariable` lookup strings SHALL be the Go field names (`LapiKey`, `LapiTLSClientCertificate`, `AppsecKey`, `CaptchaSiteKey`). TLS prefix helpers SHALL be `Lapi` / `Appsec` plus `TLSCertificateAuthority`, `TLSClientCertificate`, and `TLSClientKey`. Validation errors SHALL name the Go field.

#### Scenario: Old crowdsec key is ignored
- **WHEN** operator YAML sets only `crowdsecLapiHost` and omits `lapiHost`
- **THEN** Traefik decode leaves `LapiHost` at the CreateConfig default
- **AND** the old key is not a field on `Config`

#### Scenario: GetVariable uses the new field name
- **WHEN** `GetVariable` is called with `LapiKey` and `LapiKeyFile` names a readable file
- **THEN** the lookup returns that file’s trimmed contents
- **AND** a call with `CrowdsecLapiKey` does not resolve `LapiKeyFile`

#### Scenario: Captcha own-axis keys are captcha-prefixed
- **WHEN** the operator sets `captchaEnabled` and `captchaInstanceName`
- **THEN** those keys decode onto `CaptchaEnabled` and `CaptchaInstanceName`
- **AND** owner-read settings are `captcha*`

#### Scenario: Old bouncerCaptcha key is ignored
- **WHEN** operator YAML sets only `bouncerCaptchaSiteKey` and omits `captchaSiteKey`
- **THEN** Traefik decode leaves `CaptchaSiteKey` at the CreateConfig default
- **AND** the old key is not a field on `Config`

### Requirement: Independent HTTP timeout knobs
`Config` SHALL expose `LapiHTTPTimeoutSeconds` (`lapiHttpTimeoutSeconds`), `AppsecHTTPTimeoutSeconds` (`appsecHttpTimeoutSeconds`), and `CaptchaSiteverifyHTTPTimeoutSeconds` (`captchaSiteverifyHttpTimeoutSeconds`). `CreateConfig` and `configuration.New` SHALL default each to 10. `ValidateParams` SHALL reject any of those knobs less than 1 (`cannot be less than 1`). `Config` MUST NOT expose `HTTPTimeoutSeconds`, `httpTimeoutSeconds`, or `EffectiveHTTPTimeoutSeconds`. Setting one timeout MUST NOT move the others. An omitted AppSec scheme or key MAY still copy from LAPI when AppSec is owned; the AppSec timeout MUST NOT copy.

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

### Requirement: Captcha own-axis keys and default
`Config` SHALL expose `captchaEnabled` (Go `CaptchaEnabled`, default false) and `captchaInstanceName` (Go `CaptchaInstanceName`, default empty). `CreateConfig` MUST NOT default `captchaEnabled` true from a set `captchaProvider`. Owner-style captcha checks (provider, site/secret keys, gate secret, loadable template, custom-validate body tokens) SHALL run only when `captchaEnabled` is true. A subscriber leftover owner-read `captcha*` MUST NOT fail those checks. Empty secret SHALL fail those checks only when the provider is not `recaptcha-enterprise`.

#### Scenario: Default is false
- **WHEN** the operator omits `captchaEnabled`
- **THEN** `CreateConfig` leaves it false
- **AND** a set `captchaProvider` does not own captcha

#### Scenario: Subscriber leftover keys do not fail ValidateParams
- **WHEN** `captchaEnabled` is false, `bouncerEnabled` is true, `captchaInstanceName` is `shared`, and leftover `captchaProvider` is set with empty keys
- **THEN** `ValidateParams` returns no error from owner-style captcha checks

#### Scenario: Owner missing keys fail
- **WHEN** `captchaEnabled` is true and site resolves empty
- **THEN** `ValidateParams` returns an error that names the empty key

#### Scenario: Owner missing secret fails except enterprise
- **WHEN** `captchaEnabled` is true, the provider is `hcaptcha`, `recaptcha`, `turnstile`, `custom`, or `eucaptcha`, and secret resolves empty
- **THEN** `ValidateParams` returns an error that names the empty secret
