## ADDED Requirements

### Requirement: A LAPI ban answered 429 carries Retry-After
When the bouncer writes a ban with status 429 and a LAPI decision with a known end is behind it, the response SHALL set `Retry-After` to the seconds left on that decision, rounded up (at least `1`), before `WriteHeader`. That decision SHALL be the one the lookup chose, kept through remap and action rules. Any other status, an unknown end, or a ban no LAPI decision is behind (AppSec, failure action, cache failure, action rule) MUST NOT set `Retry-After`.

#### Scenario: Stream ban answered 429 carries the time left
- **WHEN** `bouncerRemediationStatusCode` is 429 and the store holds an Ip ban for the client with 3600 seconds left
- **THEN** the response status is 429
- **AND** `Retry-After` is an integer from `1` to `3600`

#### Scenario: Ban answered 403 has no Retry-After
- **WHEN** `bouncerRemediationStatusCode` is 403 and the store holds an Ip ban for the client with 3600 seconds left
- **THEN** the response has no `Retry-After`

#### Scenario: Live miss ban carries the LAPI duration
- **WHEN** `lapiMode` is live or none, `bouncerRemediationStatusCode` is 429, and LAPI returns a ban for the client with duration `90m`
- **THEN** `Retry-After` is an integer from `1` to `5400`

#### Scenario: Live cached ban reports the decision end, not the cache end
- **WHEN** `lapiMode` is live, `lapiDefaultDecisionSeconds` is 60, `bouncerRemediationStatusCode` is 429, and LAPI returned a ban with duration `4h` that the store memoized
- **AND** a later request from the same client hits that memo
- **THEN** `Retry-After` is greater than `60`

#### Scenario: AppSec ban with http_status 429 has no Retry-After
- **WHEN** AppSec answers `ban` with `http_status` 429 and LAPI holds no decision for the client
- **THEN** the response status is 429
- **AND** the response has no `Retry-After`

#### Scenario: Failure-action ban has no Retry-After
- **WHEN** `bouncerRemediationStatusCode` is 429, `bouncerLapiFailureAction` is `ban`, and the LAPI lookup fails
- **THEN** the response status is 429
- **AND** the response has no `Retry-After`

#### Scenario: Cache-failure ban has no Retry-After
- **WHEN** `bouncerRemediationStatusCode` is 429 and `Store.LookupRemediation` returns an error that bans
- **THEN** the response has no `Retry-After`

#### Scenario: Action-rule ban has no Retry-After
- **WHEN** `bouncerRemediationStatusCode` is 429 and a matching `bouncerActionRules` row carries `ban`
- **THEN** the response status is 429
- **AND** the response has no `Retry-After`, even when the store also holds a ban for the client

#### Scenario: LAPI captcha served as a ban carries Retry-After
- **WHEN** `bouncerRemediationStatusCode` is 429, this router did not subscribe to a captcha, and the store holds an Ip captcha for the client with 600 seconds left
- **THEN** the response is a ban with status 429
- **AND** `Retry-After` is an integer from `1` to `600`

#### Scenario: Captcha challenge has no Retry-After
- **WHEN** this router has a usable captcha client and the store holds an Ip captcha for the client
- **THEN** the challenge page is served
- **AND** the response has no `Retry-After`

#### Scenario: Captcha rule that loses to a LAPI ban carries Retry-After
- **WHEN** `bouncerRemediationStatusCode` is 429, a matching `bouncerActionRules` row carries `captcha`, and the store holds an Ip ban for the client with 3600 seconds left
- **THEN** the response is a ban with status 429
- **AND** `Retry-After` is an integer from `1` to `3600`

#### Scenario: HEAD ban carries Retry-After
- **WHEN** `bouncerRemediationStatusCode` is 429, the request method is HEAD, and the store holds an Ip ban for the client with 3600 seconds left
- **THEN** `Retry-After` is set
- **AND** the body is empty

#### Scenario: Stream Range ban has no Retry-After
- **WHEN** `lapiMode` is stream, `bouncerRemediationStatusCode` is 429, and only a Range ban containing the client address matches
- **THEN** the response status is 429
- **AND** the response has no `Retry-After`

## MODIFIED Requirements

### Requirement: Live stream and alone lookup uses one Store entry
When `lapiMode` is live, stream, or alone, and no matching action rule skipped LAPI and no matching action rule banned, the bouncer SHALL resolve memoized remediation through one `lapi.Client.LookupRemediation` that delegates to `Store.LookupRemediation`, which returns kind, origin, origin id, and the winning decision's time left. It MUST NOT call `UsesLiveSnapshot`, MUST NOT branch between a live snapshot and a cache Client, and MUST NOT duplicate merge semantics in the bouncer. Stream and alone miss SHALL fall through to stream-healthy / failure-action. Live miss SHALL call `LiveLookup`, which returns `(kind, origin, decision time left, error)` fields. A zero time left means the end is unknown. None mode SHALL call `LiveLookup` every request (no memo read) unless a matching action rule skipped LAPI or a matching action rule banned. Action-rule skip and ban are owned by the action-rules requirement on this leaf; this lookup requirement MUST NOT restate those SHALL. `bouncer.New` SHALL copy `LapiDefaultDecisionSeconds` onto `Bouncer.defaultDecisionSeconds` and pass that into `LiveLookup`; the parameter name SHALL stay `defaultDecisionSeconds`.

#### Scenario: Stream mode uses Store lookup
- **WHEN** a stream bouncer handles a request and the DecisionStore is memory-backed
- **AND** no matching action rule skipped LAPI
- **AND** no matching action rule banned
- **THEN** remediation is resolved through `LookupRemediation` only

#### Scenario: Stream mode Redis uses the same entry
- **WHEN** a stream bouncer handles a request and the DecisionStore is Redis-backed
- **AND** no matching action rule skipped LAPI
- **AND** no matching action rule banned
- **THEN** remediation is resolved through the same `LookupRemediation`

#### Scenario: Live memo then LiveLookup
- **WHEN** `lapiMode` is live and the Store misses
- **AND** no matching action rule skipped LAPI
- **AND** no matching action rule banned
- **THEN** the bouncer calls `LiveLookup` and remediates from kind and origin fields

#### Scenario: None mode skips Store memo
- **WHEN** `lapiMode` is none
- **AND** no matching action rule skipped LAPI
- **AND** no matching action rule banned
- **THEN** the bouncer does not use a Store hit as the primary remediation check
- **AND** it calls `LiveLookup` for kind and origin
