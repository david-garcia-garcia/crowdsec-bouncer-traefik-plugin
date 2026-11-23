## MODIFIED Requirements

### Requirement: Failure messages name what actually failed
A failed LAPI/CAPI exchange SHALL produce a message that names its own cause. A transport error SHALL wrap that error. A reverse-proxy status SHALL name the status code and MUST NOT wrap a `nil` error, so `%!w(<nil>)` never reaches an operator. A non-2xx answer, reverse-proxy statuses included, SHALL be returned as a status error that carries the HTTP status code, so a caller can read the code without parsing the message. That error's message SHALL keep its text: `crowdsecQuery:unreachable url:<url> statusCode:<code>` for 502, 503, and 504, and `crowdsecQuery method:<method> url:<url>, statusCode:<code> (expected: 2xx)` for any other non-2xx. Callers that do not read the status code SHALL see no change.

#### Scenario: Reverse-proxy status names the code
- **WHEN** LAPI answers `503`
- **THEN** the returned message contains the request URL and the status code `503`
- **AND** it does not contain `%!w(<nil>)`

#### Scenario: Transport error keeps its cause
- **WHEN** the HTTP transport fails to reach LAPI
- **THEN** the returned message wraps that transport error

#### Scenario: Non-2xx carries its status code
- **WHEN** LAPI answers `429`, `401`, or `503`
- **THEN** the returned error exposes that status code to the caller
- **AND** its message keeps the text named above for that status

#### Scenario: Transport error carries no status code
- **WHEN** the HTTP transport fails to reach LAPI
- **THEN** the returned error is not a status error
