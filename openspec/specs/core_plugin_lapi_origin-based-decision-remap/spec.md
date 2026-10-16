## Purpose

Maps selected LAPI decision types to a weaker kind at Bouncer apply using public Config `OriginBasedDecisionRemap` and `MetricsOrigin`, including per-list `lists:<name>` matching. LAPI and the DecisionStore keep the original kind.

## Requirements

### Requirement: Empty OriginBasedDecisionRemap leaves kinds unchanged
Public Config `OriginBasedDecisionRemap` (`json:"originBasedDecisionRemap"`) SHALL default to empty. When the Bouncer table is empty, a LAPI decision type `ban` SHALL store and apply as kind `t` (`BannedValue`) and type `captcha` SHALL store and apply as kind `c` (`CaptchaValue`). `ValidateParams` MUST NOT reject unknown origin tokens and MUST NOT require `captchaProvider` for this table. Blank origin keys SHALL be dropped when copied onto the Bouncer.

#### Scenario: Default config still bans CAPI
- **WHEN** `originBasedDecisionRemap` is empty or omitted and LAPI returns type `ban` origin `CAPI`
- **THEN** the stored kind is ban (`t`)
- **AND** ServeHTTP remediates as ban

### Requirement: Origin remap is one hop at Bouncer apply
`lapi.Client` stream Put, stream Range upsert, live/none query, and live cache SHALL store `ban` as kind `t` (`BannedValue`) and `captcha` as kind `c` (`CaptchaValue`). A LAPI type that is neither `ban` nor `captcha` SHALL store as ban (`t`). `RemediationValue` MUST still return empty for those unknown types so origin remap and other callers can treat empty as not a remediation code. The match key at apply SHALL be `MetricsOrigin` of the looked-up decision. A second edge on the same origin MUST NOT apply to the result of the first. An unknown type SHALL be logged at TRACE with message stem `handleStreamCache:unknownType` and MUST NOT be logged at Info or Debug.

Allowed edges SHALL be weaken-only: `ban` to `captcha` or `pass`; `captcha` to `pass`. `pass` SHALL apply as no LAPI remediation (`NoBannedValue`) and then AppSec/next. `ValidateParams` MUST reject any other from/to pair.

#### Scenario: CAPI ban stores ban and applies captcha
- **WHEN** `originBasedDecisionRemap` is `{CAPI: {ban: captcha}}` and a stream `ban` has origin `CAPI`
- **THEN** the Ip slot kind is ban (`t`)
- **AND** ServeHTTP remediates as captcha (`c`)

#### Scenario: Unlisted origin stays ban
- **WHEN** `originBasedDecisionRemap` is `{CAPI: {ban: captcha}, lists: {ban: captcha}}` and a `ban` has origin `cscli`
- **THEN** the stored kind is ban (`t`)
- **AND** ServeHTTP remediates as ban

#### Scenario: Captcha pass keeps the stored captcha
- **WHEN** `originBasedDecisionRemap` is `{crowdsec: {captcha: pass}}` and a stream `captcha` has origin `crowdsec`
- **THEN** the Ip slot kind is captcha (`c`)
- **AND** ServeHTTP does not serve a captcha page
- **AND** AppSec/next still run

#### Scenario: Ban plus captcha pass on the same origin does not chain
- **WHEN** `originBasedDecisionRemap` is `{CAPI: {ban: captcha, captcha: pass}}` and the stored kind is ban (`t`) origin `CAPI`
- **THEN** ServeHTTP remediates as captcha (`c`)

#### Scenario: Invalid edge fails validation
- **WHEN** `originBasedDecisionRemap` is `{CAPI: {captcha: ban}}`
- **THEN** `ValidateParams` returns an error

#### Scenario: Stream challenge stores ban
- **WHEN** a stream New Ip decision has type `challenge`
- **THEN** the Ip slot kind is ban (`t`)

#### Scenario: Stream Range unknown type stores ban
- **WHEN** a stream New Range decision has type `allow` and a non-empty CIDR
- **THEN** Range membership remediates that CIDR as ban (`t`)

#### Scenario: Unknown type logs at TRACE
- **WHEN** LAPI ingest maps a type that is neither `ban` nor `captcha`
- **THEN** a TRACE record message is `handleStreamCache:unknownType`
- **AND** no Info or Debug record uses that stem for that item

### Requirement: lists matches every list; lists:name matches one list
Config key `lists` SHALL match metrics origin `lists` and any origin with prefix `lists:`. Config key `lists:<name>` SHALL match only that exact metrics origin and SHALL win over a `lists` key. Other keys SHALL be exact equality. Match SHALL be case-sensitive.

#### Scenario: One list remaps
- **WHEN** `originBasedDecisionRemap` is `{lists:firehol_level1: {ban: captcha}}` and a stored `ban` has origin `lists:firehol_level1`
- **THEN** ServeHTTP remediates as captcha (`c`)

#### Scenario: Other list stays ban
- **WHEN** the same config and a stored `ban` has origin `lists:tor-exit`
- **THEN** ServeHTTP remediates as ban

#### Scenario: Bare lists key remaps every list
- **WHEN** `originBasedDecisionRemap` is `{lists: {ban: captcha}}` and a stored `ban` has origin `lists:tor-exit`
- **THEN** ServeHTTP remediates as captcha (`c`)

### Requirement: Live strongest pick uses LAPI type
`queryLiveDecisions` SHALL pick among LAPI decisions using the ingest kind: the first ban (including a type that is neither `ban` nor `captcha`) wins, else the first captcha. An empty decision list SHALL be no-remediation. It MUST NOT apply `OriginBasedDecisionRemap` when picking or when writing the live cache.

#### Scenario: First live ban is cached as ban
- **WHEN** live returns a CAPI `ban` then a `crowdsec` `ban`
- **THEN** the cached kind is ban (`t`) from the CAPI decision

#### Scenario: Live challenge is ban
- **WHEN** live returns one decision of type `challenge`
- **THEN** the result kind is ban (`t`)

#### Scenario: Empty live list is no-remediation
- **WHEN** live returns an empty decision list
- **THEN** the result kind is no-remediation (`f`)

#### Scenario: Unknown type outranks captcha
- **WHEN** live returns type `allow` then type `captcha`
- **THEN** the result kind is ban (`t`) from the `allow` decision

### Requirement: OriginBasedDecisionRemap is per Bouncer
`bouncer.New` SHALL copy `OriginBasedDecisionRemap` onto that Bouncer. The table MUST NOT appear in stream `SessionKey` or live/none `Key`. Two Bouncers sharing one Client MAY disagree. Stream apply MUST NOT use the first `New` table.

#### Scenario: Two routers disagree
- **WHEN** two stream `New` calls share LAPI URL, key, and Redis and disagree only on `originBasedDecisionRemap`
- **THEN** they reuse one Client and one Store
- **AND** each Bouncer applies its own table at ServeHTTP
