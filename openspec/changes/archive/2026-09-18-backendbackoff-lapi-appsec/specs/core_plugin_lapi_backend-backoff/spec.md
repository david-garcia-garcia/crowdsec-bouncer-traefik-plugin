## Purpose

Admits live/none CrowdSec LAPI HTTP through the published `backendbackoff` Gate so a dead LAPI is not contacted on every request, while stream/alone stays on `UpdateMaxFailure`.

## ADDED Requirements

### Requirement: Live and none LAPI Clients own one published Gate
A live or none `lapi.Client` SHALL construct one `backendbackoff.Gate` at create time from the shared plugin backoff knobs. Stream and alone Clients MUST NOT construct a Gate. The package SHALL import `github.com/david-garcia-garcia/traefik-middleware-utilities/backendbackoff` and MUST NOT copy that package into `pkg/`, MUST NOT add `pkg/health`, and MUST NOT import traefik-modsecurity. Sleep and Wake MUST NOT touch the Gate. The knobs MUST NOT join the LAPI reclaim key; a later `New` that differs only on those knobs SHALL reuse the same Client (silent first-wins, same as `updateMaxFailure`).

#### Scenario: Live Client has a Gate
- **WHEN** a live-mode Client is constructed
- **THEN** that Client owns one Gate built from the plugin backoff knobs

#### Scenario: Stream Client has no Gate
- **WHEN** a stream-mode Client is constructed
- **THEN** that Client has no Gate
- **AND** stream polls still use `UpdateMaxFailure` / `StreamHealthy`

### Requirement: Each live LAPI GET is admitted before the HTTP attempt
Before each live or none LAPI GET (the client-address query and each mapped header-scope query), the Client SHALL call `Allow` with the inbound request `Context` and the backend URL stem the Client already composes for that attempt (`scheme` + `host` + `path`, without the query string). The key MUST NOT be the client address and MUST NOT be the reclaim key. Client address, when this leaf mentions it, SHALL reuse `pkg/ip.GetRemoteIP` via `clientRequest.remoteIP`. The call MUST NOT sleep on Allow's wait; it SHALL Debug-log that wait. A nil Gate SHALL admit (no-op). Constructor context and `context.Background()` MUST NOT be used for Allow.

#### Scenario: Denied GET does not hit LAPI
- **WHEN** Allow returns `ok=false` and `err=nil` for the LAPI URL stem
- **THEN** no HTTP GET is sent to LAPI for that query
- **AND** the lookup reports a query error with a skip message that is not `unreachable` or `banned`

#### Scenario: Later scope GET also skips after the Gate trips
- **WHEN** the client-address GET was Reported as failure enough times to trip the Gate
- **AND** a later lookup maps a header scope
- **THEN** that header-scope GET is also denied
- **AND** no HTTP GET is sent for that scope

#### Scenario: Cache hit never Allows
- **WHEN** `Bouncer.ServeHTTP` finds a live-cache hit
- **THEN** `LiveLookup` is not called
- **AND** Allow is not called

### Requirement: Denied or Allow-error uses today's LAPI failure path
A denied Allow or an Allow error SHALL be reported as a live query error with a non-active remediation, so existing fail-closed, active-ban-outranks, and `crowdsecLapiFailureAction` stay. No new action enum SHALL be added. Denied Allows MUST NOT be Reported.

#### Scenario: Denied IP query applies FailureAction
- **WHEN** the client-address GET is denied and `crowdsecLapiFailureAction` is `ban`
- **THEN** the caller sees a non-active remediation plus a query error
- **AND** the request is forbidden

#### Scenario: Active ban still outranks a denied scope GET
- **WHEN** the client-address GET returns an active ban and a later header-scope Allow is denied
- **THEN** that ban is the outcome
- **AND** `crowdsecLapiFailureAction` is not consulted

### Requirement: Admitted LAPI attempts Report backend health
After an admitted GET, the Client SHALL `Report` on the same URL stem. Report success SHALL be any HTTP+parse that yielded a remediation value (ban, captcha, or none). Report failure SHALL be query, HTTP, parse, or duration-parse errors. A backend that answered is healthy regardless of remediation kind. Metrics POST and stream poll HTTP MUST NOT call Allow or Report.

#### Scenario: Captcha answer Reports success
- **WHEN** an admitted GET returns a captcha remediation
- **THEN** Report is called with success
- **AND** the captcha remediation is the lookup result

#### Scenario: Parse error Reports failure
- **WHEN** an admitted GET returns a body that cannot be parsed
- **THEN** Report is called with failure
- **AND** the lookup reports a query error

#### Scenario: Success Report recovers
- **WHEN** the Gate is OPEN after failures
- **AND** a later admitted GET returns no decision
- **THEN** Report is called with success
- **AND** a following lookup is admitted again

### Requirement: Client Close closes the Gate
`lapi.Client.Close` SHALL close a non-nil Gate. A nil Gate Close SHALL be a no-op. Close MUST remain safe to call more than once.

#### Scenario: Live Close closes the Gate
- **WHEN** a live Client is Closed
- **THEN** a later Allow on that Gate does not admit
