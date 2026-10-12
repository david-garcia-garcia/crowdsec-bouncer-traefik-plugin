## Purpose

`package modsecurity` owns the reclaim value for one OWASP CRS sidecar listener. It copies requests for inspection and does not speak CrowdSec AppSec JSON.

## ADDED Requirements

### Requirement: ModSecurity lives in package modsecurity
`package modsecurity` SHALL own the reclaim value for one CRS sidecar listener. The exported type SHALL be `Client`. The package MUST NOT import `pkg/appsec` or `pkg/lapi` and MUST NOT speak CrowdSec AppSec JSON (`X-Crowdsec-Appsec-*` or AppSec `action` envelopes).

#### Scenario: Bouncer inspects through modsecurity.Client
- **WHEN** `pkg/bouncer` compiles against this package
- **THEN** a ModSec inspect call resolves on `modsecurity.Client`
- **AND** the call does not go through `appsec.Client`

### Requirement: ModSecurity is reclaimed by sidecar identity
When `modsecEnabled` is true, the owning middleware SHALL reclaim a `modsecurity.Client` with `reclaim.Open` on the process table. The reclaim ownership key SHALL be derived from the Traefik middleware name plus `modsecUrl`, `modsecHttpTimeoutSeconds`, `modsecBodyLimit`, `modsecDenyVerbsWithBody`, and the unhealthy-backoff knobs (`modsecUnhealthyBackOffPeriodSecs`, `modsecUnhealthyMaxBackOffPeriodSecs`, `modsecUnhealthyFailureThreshold`, `modsecUnhealthyFailureRatio`). Slot name, `bouncerEnabled`, bounce knobs, LAPI fields, AppSec fields, captcha fields, and per-router `bouncerModsecFailMode` MUST NOT be in that key. Two `Open` calls with different middleware names and otherwise identical ModSec knobs SHALL produce two Clients. A change to any keyed ModSec knob SHALL Open a new Client.

#### Scenario: Two middleware names do not share ModSec
- **WHEN** two owners Open ModSec with different Traefik names and identical `modsecUrl`
- **THEN** two ModSec Client incarnations exist

#### Scenario: Backoff knob change is a new Client
- **WHEN** a second Open for the same middleware name changes only `modsecUnhealthyBackOffPeriodSecs`
- **THEN** the second Open returns a different Client incarnation than the first

#### Scenario: Same name same knobs Wake
- **WHEN** the holder context for a ModSec ownership key is cancelled and a `New` with the same name and knobs runs before grace ends
- **THEN** the same ModSec Client incarnation is returned

### Requirement: Empty ModSec instance name fills only when owned
When `modsecEnabled` is true and the trimmed `modsecInstanceName` is empty, `Prepare` SHALL set the instance name to this middleware's Traefik name. When `modsecEnabled` is false, an empty name SHALL stay empty.

#### Scenario: Owner omit fills to Traefik name
- **WHEN** `modsecEnabled` is true and `modsecInstanceName` is omitted
- **AND** the Traefik middleware name is `cs-owner`
- **THEN** the published ModSec alias is `alias:modsec:cs-owner`

#### Scenario: Subscriber omit does not fill
- **WHEN** `modsecEnabled` is false, `bouncerEnabled` is true, and `modsecInstanceName` is omitted
- **THEN** the name stays empty
- **AND** the middleware does not Watch ModSec

### Requirement: ModSec Client owns the admission gate
When `modsecUnhealthyBackOffPeriodSecs` is greater than 0, the Client SHALL hold one `backendbackoff.Gate` from dest utilities `v1.0.7` and MUST NOT copy that package into this repository. When that period is 0 or omitted, the Client SHALL hold no gate (every inspect failure still follows `bouncerModsecFailMode`). Default period SHALL be `0`. Omitted threshold SHALL be `5`. Omitted ratio SHALL use the packaged `0.30`. Omitted max period SHALL equal the base period. `Jitter` and `TTL` MUST NOT be set by this plugin (partial Config, jitter stays disabled). The unused source window knob MUST NOT be a public Config field. Client `Close` SHALL Close a non-nil Gate.

#### Scenario: Omitted backoff builds no gate
- **WHEN** the operator omits `modsecUnhealthyBackOffPeriodSecs` and the sidecar returns HTTP 500
- **THEN** that request follows `bouncerModsecFailMode`
- **AND** the next request still calls the sidecar

#### Scenario: Positive backoff builds one gate
- **WHEN** `modsecUnhealthyBackOffPeriodSecs` is 30
- **THEN** the Client holds one Gate
- **AND** Client Close closes that Gate

### Requirement: Deny-verbs-with-body default list
Omitted or nil `modsecDenyVerbsWithBody` SHALL be `HEAD`, `GET`, `DELETE`, `OPTIONS`, `TRACE`, `CONNECT`. An explicit empty list SHALL deny nothing. A listed method with a readable body byte SHALL be HTTP 400, MUST NOT call the sidecar, and MUST NOT call `next`, including after the gate has tripped.

#### Scenario: Default GET with body is 400
- **WHEN** `modsecDenyVerbsWithBody` is omitted
- **AND** a GET carries a readable body
- **THEN** the response is HTTP 400
- **AND** the sidecar is not called

#### Scenario: Explicit empty list inspects GET with body
- **WHEN** `modsecDenyVerbsWithBody` is an empty list
- **AND** a GET carries a readable body
- **THEN** the sidecar is called

### Requirement: ModSec body limit default and zero
Omitted `modsecBodyLimit` SHALL be 8388608 (8 MiB). `0` SHALL mean unlimited. A positive limit SHALL cap the inbound copy; exceeding it SHALL be HTTP 413 and MUST NOT call the sidecar.

#### Scenario: Omitted limit is 8 MiB
- **WHEN** `modsecBodyLimit` is omitted
- **AND** the client POST exceeds 8388608 bytes
- **THEN** the response is HTTP 413

#### Scenario: Zero is unlimited
- **WHEN** `modsecBodyLimit` is `0`
- **AND** the client POST exceeds 8388608 bytes
- **THEN** the sidecar receives that body
