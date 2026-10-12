## ADDED Requirements

### Requirement: Enabled ModSec requires an absolute URL
When `modsecEnabled` is true, `ValidateParams` SHALL reject an empty `modsecUrl` and any value that is not an absolute `http` or `https` URL. When `modsecEnabled` is false, `ValidateParams` MUST NOT fail solely because `modsecUrl` is empty.

#### Scenario: Enabled ModSec with empty URL is rejected
- **WHEN** `modsecEnabled` is true and `modsecUrl` is empty
- **THEN** `ValidateParams` returns an error

#### Scenario: Disabled ModSec with empty URL is accepted
- **WHEN** `modsecEnabled` is false, `modsecUrl` is empty, and the rest of the config is valid
- **THEN** `ValidateParams` returns nil

### Requirement: bouncerModsecFailMode is open or close
Public config `bouncerModsecFailMode` SHALL be `open` or `close` (case-insensitive). Empty or omitted SHALL be `open`. Other values SHALL fail `ValidateParams`. This key SHALL be per-router (not on ModSec Client identity).

#### Scenario: Default is open
- **WHEN** the operator omits `bouncerModsecFailMode`
- **THEN** failMode is `open`

#### Scenario: Unknown failMode fails New
- **WHEN** `bouncerModsecFailMode` is `ban`
- **THEN** `ValidateParams` returns an error

### Requirement: AppSec backoff knobs are non-negative
`appsecUnhealthyBackOffPeriodSecs` SHALL default to 30. `0` SHALL disable the AppSec gate. A negative period SHALL fail `ValidateParams`. When max period is greater than 0 it SHALL be greater than or equal to the base period. `appsecUnhealthyFailureRatio` when set SHALL be greater than or equal to 0 and less than 1. Omitted threshold SHALL be 5.

#### Scenario: Default AppSec backoff is 30
- **WHEN** the operator omits `appsecUnhealthyBackOffPeriodSecs`
- **THEN** the AppSec Client builds a gate with base cooldown 30 seconds

#### Scenario: Zero disables the AppSec gate
- **WHEN** `appsecUnhealthyBackOffPeriodSecs` is 0
- **THEN** the AppSec Client holds no gate

## MODIFIED Requirements

### Requirement: Instance open versus subscribe validation
`ValidateParams` SHALL enforce the open-vs-subscribe matrix for each leg (LAPI, AppSec, captcha, and ModSec). When `bouncerEnabled` is false and the leg enable flag is false, a non-empty instance name, API key, or client certificate for that leg SHALL fail validation (E2). Captcha E2 is a leftover `captchaInstanceName` (not leftover owner-read `captcha*` keys). ModSec E2 is a leftover `modsecInstanceName` (not leftover owner-read `modsec*` keys). When `bouncerEnabled` is true, the leg enable flag is false, and the instance name is omitted after prepopulation rules, the bouncer SHALL NOT subscribe and validation SHALL succeed without treating the leg as open (E3). When a LAPI or AppSec enable flag is true and neither API key nor client certificate can build that client, `ValidateParams` or subsequent `Open` failure SHALL fail `New` for that middleware. When `captchaEnabled` is true, owner-style captcha checks SHALL fail `New` if provider, keys, or gate secret cannot build the client. When `modsecEnabled` is true, owner-style ModSec checks SHALL fail `New` if `modsecUrl` cannot build the client. An empty or unloadable captcha template MUST NOT fail `New`.

#### Scenario: Leftover instance name with nothing enabled fails
- **WHEN** `bouncerEnabled` is false, `lapiEnabled` is false, and `lapiInstanceName` is `shared`
- **THEN** `ValidateParams` returns an error

#### Scenario: Bouncer with LAPI leg off and no name succeeds
- **WHEN** `bouncerEnabled` is true, `lapiEnabled` is false, AppSec is disabled, and `lapiInstanceName` is omitted
- **THEN** `ValidateParams` returns no error

#### Scenario: Leftover captcha instance name with nothing enabled fails
- **WHEN** `bouncerEnabled` is false, `captchaEnabled` is false, and `captchaInstanceName` is `shared`
- **THEN** `ValidateParams` returns an error

#### Scenario: Leftover ModSec instance name with nothing enabled fails
- **WHEN** `bouncerEnabled` is false, `modsecEnabled` is false, and `modsecInstanceName` is `shared`
- **THEN** `ValidateParams` returns an error

### Requirement: Public Config keys use domain prefixes
`Config` SHALL expose flat public JSON keys whose first syllable is the piece that reads them (`lapi`, `appsec`, `bouncer`, `captcha`, `modsec`). Own-axis captcha keys SHALL be `captchaEnabled` and `captchaInstanceName`. Owner-read captcha settings SHALL be `captcha*` (`Captcha*` Go fields). Own-axis ModSec keys SHALL be `modsecEnabled` and `modsecInstanceName`. Owner-read ModSec settings SHALL be `modsec*` (`Modsec*` Go fields). Per-router ModSec failMode SHALL be `bouncerModsecFailMode`. The plugin MUST NOT accept old `bouncerCaptcha*` keys as aliases. Logging keys (`logLevel`, `logFormat`, `logFilePath`) and `reclaimGraceSeconds` SHALL stay unprefixed. The plugin MUST NOT accept old `crowdsec*` keys, source-plugin `modSecurityUrl` camelCase, or unprefixed router knobs as aliases, and MUST NOT nest those maps. `GetVariable` lookup strings SHALL be the Go field names (`LapiKey`, `LapiTLSClientCertificate`, `AppsecKey`, `CaptchaSiteKey`). TLS prefix helpers SHALL be `Lapi` / `Appsec` plus `TLSCertificateAuthority`, `TLSClientCertificate`, and `TLSClientKey`. Validation errors SHALL name the Go field.

#### Scenario: Old crowdsec key is ignored
- **WHEN** operator YAML sets only `crowdsecLapiHost` and omits `lapiHost`
- **THEN** Traefik decode leaves `LapiHost` at the CreateConfig default
- **AND** the old key is not a field on `Config`

#### Scenario: GetVariable uses the new field name
- **WHEN** `GetVariable` is called with `LapiKey` and `LapiKeyFile` names a readable file
- **THEN** the lookup returns that file's trimmed contents
- **AND** a call with `CrowdsecLapiKey` does not resolve `LapiKeyFile`

#### Scenario: Captcha own-axis keys are captcha-prefixed
- **WHEN** the operator sets `captchaEnabled` and `captchaInstanceName`
- **THEN** those keys decode onto `CaptchaEnabled` and `CaptchaInstanceName`
- **AND** owner-read settings are `captcha*`

#### Scenario: Old bouncerCaptcha key is ignored
- **WHEN** operator YAML sets only `bouncerCaptchaSiteKey` and omits `captchaSiteKey`
- **THEN** Traefik decode leaves `CaptchaSiteKey` at the CreateConfig default
- **AND** the old key is not a field on `Config`

#### Scenario: ModSec own-axis keys are modsec-prefixed
- **WHEN** the operator sets `modsecEnabled` and `modsecInstanceName`
- **THEN** those keys decode onto `ModsecEnabled` and `ModsecInstanceName`
- **AND** owner-read settings are `modsec*`

#### Scenario: Source camelCase URL is ignored
- **WHEN** operator YAML sets only `modSecurityUrl` and omits `modsecUrl`
- **THEN** Traefik decode leaves `ModsecUrl` empty
- **AND** the source key is not a field on `Config`
