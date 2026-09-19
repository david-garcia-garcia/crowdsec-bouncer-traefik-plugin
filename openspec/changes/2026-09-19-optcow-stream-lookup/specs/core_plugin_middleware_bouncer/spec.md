## ADDED Requirements

### Requirement: Stream and alone lookup uses one Client entry
When `crowdsecMode` is stream or alone, the bouncer SHALL resolve remediation through one `lapi.Client` stream lookup method that delegates to the DecisionStore stream store and Range membership. It MUST NOT call `UsesLiveSnapshot`, MUST NOT branch between live snapshot and cached lookup, and MUST NOT duplicate merge semantics in the bouncer. Live and none modes SHALL keep their existing cached and live lookup paths unchanged.

#### Scenario: Stream mode does not branch on snapshot flag
- **WHEN** a stream bouncer handles a request and the DecisionStore is memory-backed
- **THEN** remediation is resolved through the Client stream lookup method only

#### Scenario: Stream mode Redis uses the same entry
- **WHEN** a stream bouncer handles a request and the DecisionStore is Redis-backed
- **THEN** remediation is resolved through the same Client stream lookup method

#### Scenario: Live mode unchanged
- **WHEN** `crowdsecMode` is live or none
- **THEN** the bouncer does not call the stream lookup method for the primary remediation check
