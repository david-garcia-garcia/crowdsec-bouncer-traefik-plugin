## Purpose

Maps selected LAPI decision types to a weaker stored kind using public Config `OriginBasedDecisionRemap` and `MetricsOrigin`, including per-list `lists:<name>` matching.

## Requirements

### Requirement: Empty OriginBasedDecisionRemap leaves kinds unchanged
Public Config `OriginBasedDecisionRemap` (`json:"originBasedDecisionRemap"`) SHALL default to empty. When the Client table is empty, a LAPI decision type `ban` SHALL store kind `t` (`BannedValue`) and type `captcha` SHALL store kind `c` (`CaptchaValue`) on stream Ip/header, stream Range, and live/none query. `ValidateParams` MUST NOT reject unknown origin tokens and MUST NOT require `captchaProvider` for this table. Blank origin keys SHALL be dropped when copied onto the Client.

#### Scenario: Default config still bans CAPI
- **WHEN** `originBasedDecisionRemap` is empty or omitted and LAPI returns type `ban` origin `CAPI`
- **THEN** the stored kind is ban (`t`)

### Requirement: Origin remap is one hop on the original type
When `MetricsOrigin(origin, scenario)` matches a table key, stream Ip/header Put, stream Range upsert, and live/none query/cache SHALL store the mapped kind for that decision's original LAPI type only. A second edge on the same origin MUST NOT apply to the result of the first. An unknown type SHALL stay empty (skip store), same as `RemediationValue` today. The match key SHALL be `MetricsOrigin`; the plugin MUST NOT match raw `decision.Origin` alone. Origin strings on the Store SHALL remain the metrics origin.

Allowed edges SHALL be weaken-only: `ban` → `captcha` or `pass`; `captcha` → `pass`. `pass` SHALL be empty stored kind (skip store / live none). `ValidateParams` MUST reject any other from/to pair.

#### Scenario: CAPI ban stores captcha
- **WHEN** `originBasedDecisionRemap` is `{CAPI: {ban: captcha}}` and a stream `ban` has origin `CAPI`
- **THEN** the Ip slot kind is captcha (`c`)
- **AND** the stored origin is `CAPI`

#### Scenario: Unlisted origin stays ban
- **WHEN** `originBasedDecisionRemap` is `{CAPI: {ban: captcha}, lists: {ban: captcha}}` and a `ban` has origin `cscli`
- **THEN** the stored kind is ban (`t`)

#### Scenario: Captcha pass skips store
- **WHEN** `originBasedDecisionRemap` is `{crowdsec: {captcha: pass}}` and a stream `captcha` has origin `crowdsec`
- **THEN** the decision is not stored
- **AND** lookup for that IP is no remediation (`f`)

#### Scenario: Ban plus captcha pass on the same origin does not chain
- **WHEN** `originBasedDecisionRemap` is `{CAPI: {ban: captcha, captcha: pass}}` and a stream `ban` has origin `CAPI`
- **THEN** the stored kind is captcha (`c`)

#### Scenario: Invalid edge fails validation
- **WHEN** `originBasedDecisionRemap` is `{CAPI: {captcha: ban}}`
- **THEN** `ValidateParams` returns an error

### Requirement: lists matches every list; lists:name matches one list
Config key `lists` SHALL match metrics origin `lists` and any origin with prefix `lists:`. Config key `lists:<name>` SHALL match only that exact metrics origin and SHALL win over a `lists` key. Other keys SHALL be exact equality. Match SHALL be case-sensitive.

#### Scenario: One list remaps
- **WHEN** `originBasedDecisionRemap` is `{lists:firehol_level1: {ban: captcha}}` and a `ban` has origin `lists` and scenario `firehol_level1`
- **THEN** the stored kind is captcha (`c`)

#### Scenario: Other list stays ban
- **WHEN** the same config and a `ban` has origin `lists` and scenario `tor-exit`
- **THEN** the stored kind is ban (`t`)

#### Scenario: Bare lists key remaps every list
- **WHEN** `originBasedDecisionRemap` is `{lists: {ban: captcha}}` and a `ban` has origin `lists` and scenario `tor-exit`
- **THEN** the stored kind is captcha (`c`)

### Requirement: Live strongest pick uses remapped kind
`queryLiveDecisions` SHALL pick among LAPI decisions using the remapped kind: the first still-ban wins, else the first captcha. A `pass` remap MUST NOT be a captcha pick. It MUST NOT pick the first raw `Type=="ban"` and remap afterward.

#### Scenario: Local ban beats remapped CAPI
- **WHEN** live returns a CAPI `ban` (`ban: captcha`) and a later `crowdsec` `ban` (unmapped)
- **THEN** the cached kind is ban (`t`) from the `crowdsec` decision

### Requirement: OriginBasedDecisionRemap is first-create residue
`lapi.New` SHALL copy `OriginBasedDecisionRemap` onto the Client. The table MUST NOT appear in stream `SessionKey` or live/none `Key`. A second `New` that reuses that Client SHALL keep the first copy.

#### Scenario: Second router does not split the stream
- **WHEN** two stream `New` calls share LAPI URL, key, and Redis and disagree only on `originBasedDecisionRemap`
- **THEN** they reuse one Client
- **AND** stream apply uses the first `New` table
