## Purpose

Governs the admission gate that bounds a LAPI outage in `live` and `none` mode: when `lapi.Client` builds it, which live GETs it admits, what a denied GET does, and which LAPI answers count as a failure or a success for the gate.

## Requirements

### Requirement: LAPI Client owns the live admission gate
When `lapiMode` is `live` or `none` and `lapiUnhealthyBackOffPeriodSecs` is greater than 0, `lapi.Client` SHALL hold one `pkg/admission` gate with leg `lapi` and that period as its cooldown. Default period SHALL be 10. `0` SHALL build no gate. In `stream` and `alone` no gate SHALL be built and the key SHALL be ignored. Client `Close` SHALL close a non-nil gate. Every router that uses the Client SHALL share its gate.

#### Scenario: Omitted period builds a gate in live mode
- **WHEN** `lapiMode` is `live` and the operator omits `lapiUnhealthyBackOffPeriodSecs`
- **THEN** the LAPI Client holds one gate with cooldown 10 seconds

#### Scenario: None mode builds a gate
- **WHEN** `lapiMode` is `none` and `lapiUnhealthyBackOffPeriodSecs` is 10
- **THEN** the LAPI Client holds one gate

#### Scenario: Zero builds no gate
- **WHEN** `lapiMode` is `live` and `lapiUnhealthyBackOffPeriodSecs` is 0
- **THEN** the LAPI Client holds no gate
- **AND** every live lookup against a down LAPI still sends its GET

#### Scenario: Stream and alone build no gate
- **WHEN** `lapiMode` is `stream` or `alone` and `lapiUnhealthyBackOffPeriodSecs` is 10
- **THEN** the LAPI Client holds no gate

#### Scenario: Close closes the gate
- **WHEN** a live LAPI Client with a gate is closed
- **THEN** that gate is closed

#### Scenario: Two routers share one gate
- **WHEN** an owner middleware opens a live LAPI Client and a second router subscribes to it by instance name
- **AND** LAPI fails 5 admitted GETs from the owner's route
- **THEN** the next lookup on the subscriber's route sends no GET

### Requirement: The trip rule and log lines are the WAF gate's
The LAPI gate SHALL use the fixed trip rule of `pkg/admission` (5 failures in a row trip it) and a cooldown that does not grow. It SHALL log one WARN `crowdsec lapi backoff started` with `retryIn` on the first skipped GET after a trip, and one INFO `crowdsec lapi backoff ended` when the probe admitted during the backoff succeeds. Skipped GETs MUST NOT log one line each.

#### Scenario: Fifth failure in a row trips
- **WHEN** LAPI fails 5 admitted live GETs in a row
- **THEN** the sixth live lookup sends no GET

#### Scenario: Backoff logs once per transition
- **WHEN** the LAPI gate trips and several later lookups are skipped
- **THEN** exactly one `crowdsec lapi backoff started` line is logged
- **AND** after a probe succeeds exactly one `crowdsec lapi backoff ended` line is logged

#### Scenario: Probe after the cooldown recovers
- **WHEN** the gate is backing off and LAPI is healthy again
- **AND** the cooldown has elapsed
- **THEN** the next live lookup sends its GET and uses the LAPI answer

### Requirement: Every live GET is admitted
The gate SHALL be asked before each live GET: the client-address query and every mapped header-scope query. A live cache hit SHALL NOT consult the gate. Admission SHALL NOT wait on the inbound request context. An admission error (for example a gate closed on reclaim) SHALL be a failed lookup that uses `bouncerLapiFailureAction` and sends no GET.

#### Scenario: Header-scope GETs are gated too
- **WHEN** the gate is backing off and one header scope is mapped
- **THEN** neither the client-address GET nor the header-scope GET is sent

#### Scenario: Cache hit never consults the gate
- **WHEN** the live cache holds an answer for the client address
- **AND** the gate is backing off
- **THEN** that cached answer applies

#### Scenario: Admission error is a failure
- **WHEN** the gate returns an admission error
- **THEN** no GET is sent
- **AND** the lookup reports a failure

### Requirement: A denied GET is a gate skip
A denied admission SHALL send no HTTP request, SHALL return the sentinel `lapi.ErrGateSkip` with a non-active remediation, and SHALL write nothing to the live cache. A skipped header-scope query MUST NOT log a WARN per request.

#### Scenario: Skip writes nothing to the cache
- **WHEN** the gate denies the client-address GET
- **THEN** the lookup returns `lapi.ErrGateSkip`
- **AND** no live-cache entry is written for that client address

#### Scenario: Skipped header scope blocks the clean memo
- **WHEN** the client-address GET answers no decision and the gate denies a mapped header-scope GET
- **THEN** the lookup returns `lapi.ErrGateSkip`
- **AND** no negative live-cache entry is written for that client address

### Requirement: Mixed outcomes keep the existing lookup order
Within one lookup, an active remediation from any answered query SHALL win over a skip and over a failure. Otherwise a skipped client-address query SHALL be a skip. When the client-address query answered, the first failing header-scope query SHALL decide: a skip is `lapi.ErrGateSkip`, a real failure is a failure.

#### Scenario: Active ban outranks a skipped scope
- **WHEN** the client-address GET returns an active ban and the gate denies a header-scope GET
- **THEN** the ban is the outcome

#### Scenario: Real scope failure is a failure
- **WHEN** the client-address GET answers no decision and the first failing header-scope GET is a real failure
- **THEN** the lookup reports a failure, not a skip

### Requirement: Live GET outcomes are recorded by health
After an admitted live GET the outcome SHALL be recorded on the gate. A failure SHALL be a transport error or timeout, a missing transport, any 5xx (502, 503, and 504 included), 429, or a response-body read error. A success SHALL be any 2xx (with or without a decision, and including a JSON or duration parse error) and any 4xx other than 429. A 401 or 403 SHALL still use `bouncerLapiFailureAction`. Stream, alone, CAPI login, and the alone token renewal MUST NOT record on any gate.

#### Scenario: 401 does not trip the gate
- **WHEN** LAPI answers 401 on every live GET
- **THEN** the gate never trips
- **AND** every lookup still uses `bouncerLapiFailureAction`

#### Scenario: 503 spends the budget
- **WHEN** LAPI answers 503 on 5 live GETs in a row
- **THEN** the gate trips

#### Scenario: 429 spends the budget
- **WHEN** LAPI answers 429 on 5 live GETs in a row
- **THEN** the gate trips

#### Scenario: Parse error is a success for the gate
- **WHEN** LAPI answers 200 with a body that is not valid decision JSON
- **THEN** the gate records a success
- **AND** the lookup still uses `bouncerLapiFailureAction`

#### Scenario: Timeout spends the budget
- **WHEN** a live GET times out after `lapiHttpTimeoutSeconds`
- **THEN** the gate records a failure
