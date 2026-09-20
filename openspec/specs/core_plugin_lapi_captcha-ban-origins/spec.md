## Purpose

Maps selected LAPI `ban` origins to stored captcha kind using public Config `CaptchaBanOrigins` and `MetricsOrigin`, including per-list `lists:<name>` matching.

## Requirements

### Requirement: Empty CaptchaBanOrigins leaves ban kinds unchanged
Public Config `CaptchaBanOrigins` (`json:"captchaBanOrigins"`) SHALL default to empty. When the Client list is empty, a LAPI decision type `ban` SHALL store kind `t` (`BannedValue`) on stream Ip/header, stream Range, and live/none query. `ValidateParams` MUST NOT reject unknown origin tokens and MUST NOT require `captchaProvider` for this list. Blank entries SHALL be dropped when copied onto the Client.

#### Scenario: Default config still bans CAPI
- **WHEN** `captchaBanOrigins` is empty or omitted and LAPI returns type `ban` origin `CAPI`
- **THEN** the stored kind is ban (`t`)

### Requirement: Listed ban origins store captcha
When a decision type is `ban` and `MetricsOrigin(origin, scenario)` matches an entry, stream Ip/header Put, stream Range upsert, and live/none query/cache SHALL store captcha kind `c` (`CaptchaValue`) instead of ban. A decision type `captcha` SHALL stay captcha regardless of origin. An unknown type SHALL stay empty (skip store), same as `RemediationValue` today. The match key SHALL be `MetricsOrigin`; the plugin MUST NOT match raw `decision.Origin` alone. Origin strings on the Store SHALL remain the metrics origin (not rewritten to a captcha label).

#### Scenario: CAPI ban stores captcha
- **WHEN** `captchaBanOrigins` contains `CAPI` and a stream `ban` has origin `CAPI`
- **THEN** the Ip slot kind is captcha (`c`)
- **AND** the stored origin is `CAPI`

#### Scenario: Unlisted origin stays ban
- **WHEN** `captchaBanOrigins` is `["CAPI", "lists"]` and a `ban` has origin `cscli`
- **THEN** the stored kind is ban (`t`)

### Requirement: lists matches every list; lists:name matches one list
Config entry `lists` SHALL match metrics origin `lists` and any origin with prefix `lists:`. Config entry `lists:<name>` SHALL match only that exact metrics origin. Other entries SHALL be exact equality. Match SHALL be case-sensitive.

#### Scenario: One list remaps
- **WHEN** `captchaBanOrigins` is `["lists:firehol_level1"]` and a `ban` has origin `lists` and scenario `firehol_level1`
- **THEN** the stored kind is captcha (`c`)

#### Scenario: Other list stays ban
- **WHEN** the same config and a `ban` has origin `lists` and scenario `tor-exit`
- **THEN** the stored kind is ban (`t`)

#### Scenario: Bare lists entry remaps every list
- **WHEN** `captchaBanOrigins` is `["lists"]` and a `ban` has origin `lists` and scenario `tor-exit`
- **THEN** the stored kind is captcha (`c`)

### Requirement: Live strongest pick uses remapped kind
`queryLiveDecisions` SHALL pick among LAPI decisions using the remapped kind: the first still-ban wins, else the first captcha. It MUST NOT pick the first raw `Type=="ban"` and remap afterward.

#### Scenario: Local ban beats remapped CAPI
- **WHEN** live returns a CAPI `ban` (listed) and a later `crowdsec` `ban` (unlisted)
- **THEN** the cached kind is ban (`t`) from the `crowdsec` decision

### Requirement: CaptchaBanOrigins is first-create residue
`lapi.New` SHALL copy `CaptchaBanOrigins` onto the Client. The list MUST NOT appear in stream `SessionKey` or live/none `Key`. A second `New` that reuses that Client SHALL keep the first copy.

#### Scenario: Second router does not split the stream
- **WHEN** two stream `New` calls share LAPI URL, key, and Redis and disagree only on `captchaBanOrigins`
- **THEN** they reuse one Client
- **AND** stream apply uses the first `New` list
