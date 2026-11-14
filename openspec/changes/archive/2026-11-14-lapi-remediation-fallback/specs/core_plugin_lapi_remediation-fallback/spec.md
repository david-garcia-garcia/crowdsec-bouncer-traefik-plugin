## Purpose

Decides what the LAPI connection stores and applies for a CrowdSec decision type that is neither `ban` nor `captcha`, through one public knob `lapiRemediationFallback` (`ban`, `captcha`, or `ignore`). The LAPI stream says what to block; this knob never turns a decision into an allow.

## ADDED Requirements

### Requirement: lapiRemediationFallback accepts ban, captcha, or ignore
Public config `lapiRemediationFallback` (Go `LapiRemediationFallback`) SHALL be `ban`, `captcha`, or `ignore`. `configuration.New` SHALL default it to `ban`, and empty SHALL be treated as `ban`. `ValidateParams` SHALL reject any other value with an error that names `LapiRemediationFallback`. `captcha` MUST NOT require a captcha instance name.

#### Scenario: Default is ban
- **WHEN** the operator omits `lapiRemediationFallback`
- **THEN** `ValidateParams` returns no error
- **AND** a stream New Ip decision of type `throttle` stores as ban (`t`)

#### Scenario: Unknown knob value is rejected
- **WHEN** `lapiRemediationFallback` is `allow`
- **THEN** `ValidateParams` returns an error that names `LapiRemediationFallback`

#### Scenario: Captcha needs no captcha instance
- **WHEN** `lapiRemediationFallback` is `captcha` and `captchaEnabled` is false with no `captchaInstanceName`
- **THEN** `ValidateParams` returns no error

### Requirement: Only types other than ban and captcha follow the fallback
LAPI types `ban` and `captcha` SHALL store and apply as ban (`t`) and captcha (`c`) whatever `lapiRemediationFallback` says. Every other type SHALL follow `lapiRemediationFallback`. No type name SHALL be special-cased: `whitelist`, `allow`, `throttle`, and `challenge` MUST all follow the same knob, and none of them SHALL lift a ban held by another decision.

#### Scenario: Ban ignores the knob
- **WHEN** `lapiRemediationFallback` is `ignore` and a stream New Ip decision has type `ban`
- **THEN** the Ip slot kind is ban (`t`)

#### Scenario: Whitelist type is not an allow
- **WHEN** `lapiRemediationFallback` is `ignore`, an Ip slot holds a ban, and a stream New decision of type `whitelist` arrives for the same Ip
- **THEN** the Ip slot kind is still ban (`t`)

### Requirement: Ban and captcha fallbacks store the unknown type as that kind
When `lapiRemediationFallback` is `ban` or `captcha`, a type that is neither `ban` nor `captcha` SHALL store as ban (`t`) or captcha (`c`) respectively on stream New (Ip, header-mapped scopes, Range) and SHALL rank as that kind in the live/none strongest pick. A captcha kind on a router without a subscribed captcha SHALL take the ordinary captcha path (WARN and ban page).

#### Scenario: Captcha fallback stores captcha on stream
- **WHEN** `lapiRemediationFallback` is `captcha` and a stream New Ip decision has type `throttle`
- **THEN** the Ip slot kind is captcha (`c`)

#### Scenario: Captcha fallback on a Range
- **WHEN** `lapiRemediationFallback` is `captcha` and a stream New Range decision has type `throttle` and CIDR `10.0.0.0/8`
- **THEN** Range membership remediates a client IP inside `10.0.0.0/8` as captcha (`c`)

#### Scenario: Live ban fallback outranks captcha
- **WHEN** `lapiRemediationFallback` is `ban` and live returns type `throttle` then type `captcha`
- **THEN** the result kind is ban (`t`) from the `throttle` decision

#### Scenario: Live captcha fallback loses to ban
- **WHEN** `lapiRemediationFallback` is `captcha` and live returns type `throttle` then type `ban`
- **THEN** the result kind is ban (`t`) from the `ban` decision

### Requirement: Ignore does not store or pick unknown types
When `lapiRemediationFallback` is `ignore`, a type that is neither `ban` nor `captcha` MUST NOT be stored on stream New (Ip, header-mapped scopes, Range) and MUST NOT be picked by the live/none strongest pick. An IP whose only LAPI decisions are of such types SHALL be no-remediation (`f`).

#### Scenario: Ignored Ip decision is not stored
- **WHEN** `lapiRemediationFallback` is `ignore` and a stream New Ip decision has type `throttle`
- **THEN** that Ip slot is absent after PublishTick

#### Scenario: Ignored header-scope decision is not stored
- **WHEN** `lapiRemediationFallback` is `ignore` and a stream New decision for a header-mapped scope has type `throttle`
- **THEN** that scope slot is absent after PublishTick

#### Scenario: Ignored Range decision is not stored
- **WHEN** `lapiRemediationFallback` is `ignore` and a stream New Range decision has type `throttle` and CIDR `10.0.0.0/8`
- **THEN** `range-index` does not hold `10.0.0.0/8`

#### Scenario: Live only unknown types pass
- **WHEN** `lapiRemediationFallback` is `ignore` and live returns only decisions of type `throttle`
- **THEN** the result kind is no-remediation (`f`)

#### Scenario: Live ignored type does not hide captcha
- **WHEN** `lapiRemediationFallback` is `ignore` and live returns type `throttle` then type `captcha`
- **THEN** the result kind is captcha (`c`)

### Requirement: Ignore makes unknown-type deletes no-ops
When `lapiRemediationFallback` is `ignore`, a stream Deleted row whose type is neither `ban` nor `captcha` MUST NOT delete anything: not the Ip or header-mapped scope slot, and not the Range CIDR. When it is `ban` or `captcha`, a Deleted row SHALL keep deleting the whole slot or CIDR whatever its type.

#### Scenario: Ignored delete keeps an Ip ban
- **WHEN** `lapiRemediationFallback` is `ignore`, an Ip slot holds a ban, and a later stream poll has only a Deleted row of type `throttle` for that Ip
- **THEN** the Ip slot kind is still ban (`t`)

#### Scenario: Ignored delete keeps a Range ban
- **WHEN** `lapiRemediationFallback` is `ignore`, `range-index` holds a ban for `10.0.0.0/8`, and a later stream poll has only a Deleted Range row of type `throttle` for that CIDR
- **THEN** a client IP inside `10.0.0.0/8` is still banned

#### Scenario: Ban fallback delete still clears the slot
- **WHEN** `lapiRemediationFallback` is `ban`, an Ip slot holds a ban, and a later stream poll has only a Deleted row of type `throttle` for that Ip
- **THEN** that Ip slot is absent after PublishTick

### Requirement: The fallback belongs to the LAPI connection
`lapi.New` SHALL read `lapiRemediationFallback` from the middleware that opens the LAPI connection (`lapiEnabled: true`). A subscriber's value SHALL be unused and MUST NOT be rejected for being set. The knob MUST NOT be a per-Bouncer setting, and it MUST NOT change what happens when LAPI is unreachable; that stays `bouncerLapiFailureAction`.

#### Scenario: Subscriber value is unused
- **WHEN** the opener omits `lapiRemediationFallback` and a subscriber router sets it to `ignore`
- **THEN** a stream New Ip decision of type `throttle` stores as ban (`t`)

#### Scenario: Unreachable LAPI still uses the failure action
- **WHEN** `lapiRemediationFallback` is `ignore`, `bouncerLapiFailureAction` is `ban`, and a live LAPI query fails
- **THEN** the request remediates as ban

### Requirement: Unknown-type TRACE carries the fallback
The TRACE record `handleStreamCache:unknownType` (stem and level owned by `core_plugin_lapi_origin-based-decision-remap`) SHALL carry the type and the effective `lapiRemediationFallback`, including under `ignore`. The knob MUST NOT add an Info or Debug line.

#### Scenario: Ignored type logs at TRACE
- **WHEN** `lapiRemediationFallback` is `ignore` and LAPI ingest sees type `throttle`
- **THEN** a TRACE record message is `handleStreamCache:unknownType` with the fallback `ignore`
- **AND** no Info or Debug record uses that stem for that item
