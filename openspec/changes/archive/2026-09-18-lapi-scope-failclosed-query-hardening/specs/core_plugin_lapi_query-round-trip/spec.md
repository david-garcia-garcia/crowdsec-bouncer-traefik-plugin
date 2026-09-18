## Purpose

Governs one CrowdSec LAPI/CAPI HTTP request-response exchange: how a token renewal replays the original request, how every answered response is released so the connection can be reused, and what an operator reads when the exchange fails.

## ADDED Requirements

### Requirement: A token renewal replays the original request
When a LAPI/CAPI request answers `401` in `alone` mode, the plugin SHALL renew the CAPI token and reissue the **same** method and the **same** request body. A request that carried a body MUST NOT be replayed as a bodyless request. The replay MUST NOT be allowed to renew the token again, and the CAPI login request itself MUST NOT be allowed to renew the token, so a persistent `401` returns the status error instead of recursing without bound.

#### Scenario: POST replayed as POST after renewal
- **WHEN** `alone` mode sends a request with a body, LAPI answers `401`, and the token renewal succeeds
- **THEN** the reissued request uses the same method and carries the same body

#### Scenario: Second 401 does not retry forever
- **WHEN** the reissued request also answers `401`
- **THEN** the call returns the non-2xx status error
- **AND** no further token renewal is attempted

#### Scenario: Login 401 does not recurse
- **WHEN** the CAPI login request itself answers `401`
- **THEN** that call returns the status error without attempting a token renewal

### Requirement: Every answered response is drained and closed
When the HTTP transport returns a response, the plugin SHALL consume any remaining body bytes and close the body before returning, on **every** path: 2xx, non-2xx, and the reverse-proxy statuses `502`, `503`, and `504`. Closing without draining is not sufficient, because an unread body keeps the connection out of the idle pool. A transport error carries no response and SHALL NOT be drained. A `nil` response guard MUST NOT be added for the reverse-proxy branch: that branch is only reached when the transport returned no error, where a non-nil response is guaranteed.

#### Scenario: Reverse-proxy status reuses the connection
- **WHEN** LAPI answers `502`, `503`, or `504` with a body on repeated calls over one HTTP client
- **THEN** those calls reuse a single connection

#### Scenario: Non-2xx status reuses the connection
- **WHEN** LAPI answers a non-2xx status that is not a reverse-proxy status
- **THEN** the body is still drained and closed before the status error is returned

### Requirement: Failure messages name what actually failed
A failed LAPI/CAPI exchange SHALL produce a message that names its own cause. A transport error SHALL wrap that error. A reverse-proxy status SHALL name the status code and MUST NOT wrap a `nil` error, so `%!w(<nil>)` never reaches an operator.

#### Scenario: Reverse-proxy status names the code
- **WHEN** LAPI answers `503`
- **THEN** the returned message contains the request URL and the status code `503`
- **AND** it does not contain `%!w(<nil>)`

#### Scenario: Transport error keeps its cause
- **WHEN** the HTTP transport fails to reach LAPI
- **THEN** the returned message wraps that transport error
