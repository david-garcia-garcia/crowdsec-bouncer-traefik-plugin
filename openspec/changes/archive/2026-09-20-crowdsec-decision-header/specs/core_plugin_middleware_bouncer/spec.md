## MODIFIED Requirements

### Requirement: Live stream and alone lookup uses one Store entry
When `crowdsecMode` is live, stream, or alone, and a configured `crowdsecDecisionHeader` does not force `b` on this request, the bouncer SHALL resolve memoized remediation through one `lapi.Client.LookupRemediation` that delegates to `Store.LookupRemediation`. It MUST NOT call `UsesLiveSnapshot`, MUST NOT branch between a live snapshot and a cache Client, and MUST NOT duplicate merge semantics in the bouncer. Stream and alone miss SHALL fall through to stream-healthy / failure-action. Live miss SHALL call `LiveLookup`, which returns `(kind, origin, error)` fields. None mode SHALL call `LiveLookup` every request (no memo read) unless that same header forced `b`. Forced `b` or `c` is owned by `core_plugin_middleware_forced-decision`; this leaf MUST NOT restate that owner SHALL.

#### Scenario: Stream mode uses Store lookup
- **WHEN** a stream bouncer handles a request and the DecisionStore is memory-backed
- **AND** `crowdsecDecisionHeader` is empty or the named header is not exact trimmed `b`
- **THEN** remediation is resolved through `LookupRemediation` only

#### Scenario: Stream mode Redis uses the same entry
- **WHEN** a stream bouncer handles a request and the DecisionStore is Redis-backed
- **AND** `crowdsecDecisionHeader` is empty or the named header is not exact trimmed `b`
- **THEN** remediation is resolved through the same `LookupRemediation`

#### Scenario: Live memo then LiveLookup
- **WHEN** `crowdsecMode` is live and the Store misses
- **AND** `crowdsecDecisionHeader` is empty or the named header is not exact trimmed `b`
- **THEN** the bouncer calls `LiveLookup` and remediates from kind and origin fields

#### Scenario: None mode skips Store memo
- **WHEN** `crowdsecMode` is none
- **AND** `crowdsecDecisionHeader` is empty or the named header is not exact trimmed `b`
- **THEN** the bouncer does not use a Store hit as the primary remediation check
- **AND** it calls `LiveLookup` for kind and origin
