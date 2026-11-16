## ADDED Requirements

### Requirement: Enabled ModSec requires an absolute URL and a positive body limit
When `modsecEnabled` is true, `ValidateParams` SHALL reject an empty `modsecUrl` and any value that is not an absolute `http` or `https` URL, and SHALL reject `modsecBodyLimit` below 1 (`ModsecBodyLimit: cannot be less than 1`): the body is held in memory, so there is no unlimited value. Omitted `modsecBodyLimit` SHALL be 8388608. When `modsecEnabled` is false, `ValidateParams` MUST NOT fail solely because `modsecUrl` is empty or `modsecBodyLimit` is below 1.

#### Scenario: Enabled ModSec with empty URL is rejected
- **WHEN** `modsecEnabled` is true and `modsecUrl` is empty
- **THEN** `ValidateParams` returns an error

#### Scenario: Disabled ModSec with empty URL is accepted
- **WHEN** `modsecEnabled` is false, `modsecUrl` is empty, and the rest of the config is valid
- **THEN** `ValidateParams` returns nil

#### Scenario: Zero body limit on the ModSec owner is rejected
- **WHEN** `modsecEnabled` is true, `modsecUrl` is valid, and `modsecBodyLimit` is 0
- **THEN** `ValidateParams` returns an error naming `ModsecBodyLimit`

#### Scenario: Zero body limit without ModSec is ignored
- **WHEN** `modsecEnabled` is false and `modsecBodyLimit` is 0
- **THEN** `ValidateParams` returns nil

### Requirement: bouncerModsecFailureAction is passthrough, ban, or captcha
Public config `bouncerModsecFailureAction` SHALL be validated by the same rule as `bouncerLapiFailureAction` and `bouncerAppsecFailureAction`: empty, `passthrough`, `ban`, or `captcha`; `captcha` SHALL need a captcha instance name after owner-fill. Other values, including the old FailMode values `open` and `close`, SHALL fail `ValidateParams`. Empty or omitted SHALL be `passthrough` at runtime (`configuration.EffectiveModsecFailureAction`). This key SHALL be per-router (not on ModSec Client identity). `bouncerModsecFailMode` SHALL NOT be a Config field.

#### Scenario: Default is passthrough
- **WHEN** the operator omits `bouncerModsecFailureAction`
- **THEN** the ModSec failure action is `passthrough`

#### Scenario: Old failMode value fails New
- **WHEN** `bouncerModsecFailureAction` is `open`
- **THEN** `ValidateParams` returns an error naming `BouncerModsecFailureAction`

#### Scenario: Captcha without a captcha instance fails
- **WHEN** `bouncerModsecFailureAction` is `captcha` and the router has no captcha instance name after owner-fill
- **THEN** `ValidateParams` returns an error naming `BouncerModsecFailureAction`

### Requirement: WAF backoff periods are the only gate knobs
`appsecUnhealthyBackOffPeriodSecs` SHALL default to 30 and `modsecUnhealthyBackOffPeriodSecs` SHALL default to 0. `0` SHALL disable that leg's gate. Both SHALL be in the `requiredInt0` check: a negative period SHALL fail `ValidateParams` with `<Field>: cannot be less than 0`. There SHALL be no ratio, threshold, or max-period knob for either leg: the trip rule is fixed in `pkg/admission` (`TripFailures` 5, `FailureRatio` 0.30) and the cooldown does not grow.

#### Scenario: Default AppSec backoff is 30
- **WHEN** the operator omits `appsecUnhealthyBackOffPeriodSecs`
- **THEN** the AppSec Client builds a gate with cooldown 30 seconds

#### Scenario: Zero disables the AppSec gate
- **WHEN** `appsecUnhealthyBackOffPeriodSecs` is 0
- **THEN** the AppSec Client holds no gate

#### Scenario: Negative ModSec backoff fails
- **WHEN** `modsecUnhealthyBackOffPeriodSecs` is -1
- **THEN** `ValidateParams` returns an error naming `ModsecUnhealthyBackOffPeriodSecs`

## MODIFIED Requirements

### Requirement: Instance open versus subscribe validation
`ValidateParams` SHALL enforce the open-vs-subscribe matrix for each leg (LAPI, AppSec, captcha, and ModSec). When `bouncerEnabled` is false and the leg enable flag is false, a non-empty instance name, API key, or client certificate for that leg SHALL fail validation (E2). Captcha E2 is a leftover `captchaInstanceName` (not leftover owner-read `captcha*` keys). ModSec E2 is a leftover `modsecInstanceName` (not leftover owner-read `modsec*` keys). When `bouncerEnabled` is true, the leg enable flag is false, and the instance name is omitted after prepopulation rules, the bouncer SHALL NOT subscribe and validation SHALL succeed without treating the leg as open (E3). When a LAPI or AppSec enable flag is true and neither API key nor client certificate can build that client, `ValidateParams` or subsequent `Open` failure SHALL fail `New` for that middleware. When `captchaEnabled` is true, owner-style captcha checks SHALL fail `New` if provider, keys, or gate secret cannot build the client. When `modsecEnabled` is true, owner-style ModSec checks SHALL fail `New` if `modsecUrl` or `modsecBodyLimit` cannot build the client. An empty or unloadable captcha template MUST NOT fail `New`.

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
`Config` SHALL expose flat public JSON keys whose first syllable is the piece that reads them (`lapi`, `appsec`, `bouncer`, `captcha`, `modsec`). Own-axis captcha keys SHALL be `captchaEnabled` and `captchaInstanceName`. Owner-read captcha settings SHALL be `captcha*` (`Captcha*` Go fields). Own-axis ModSec keys SHALL be `modsecEnabled` and `modsecInstanceName`. Owner-read ModSec settings SHALL be `modsec*` (`Modsec*` Go fields). Per-router ModSec failure action SHALL be `bouncerModsecFailureAction`. The plugin MUST NOT accept old `bouncerCaptcha*` keys as aliases. Logging keys (`logLevel`, `logFormat`, `logFilePath`) and `reclaimGraceSeconds` SHALL stay unprefixed. The plugin MUST NOT accept old `crowdsec*` keys, source-plugin `modSecurityUrl` camelCase, or unprefixed router knobs as aliases, and MUST NOT nest those maps. `GetVariable` lookup strings SHALL be the Go field names (`LapiKey`, `LapiTLSClientCertificate`, `AppsecKey`, `CaptchaSiteKey`). TLS prefix helpers SHALL be `Lapi` / `Appsec` plus `TLSCertificateAuthority`, `TLSClientCertificate`, and `TLSClientKey`. Validation errors SHALL name the Go field.

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
