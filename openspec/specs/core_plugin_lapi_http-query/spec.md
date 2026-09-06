## Purpose

Governs the shared LAPI HTTP helper used by stream GET, live GET, metrics POST, and alone-mode login: safe handling of transport failures and correct alone-mode 401 retry with POST bodies.

## Requirements

### Requirement: Transport errors do not dereference a nil response
When the LAPI HTTP round trip returns a transport error or a nil response body handle, the helper SHALL return an unreachable error to callers. It MUST NOT read status code or body from a nil response. Callers SHALL treat the error as LAPI unreachable (live lookup error path or stream poll failure path as appropriate).

#### Scenario: Nil response with transport error
- **WHEN** the HTTP client returns `(nil, err)` for an LAPI request
- **THEN** the helper returns an error without panic
- **AND** no status code is read

#### Scenario: Live lookup on unreachable LAPI
- **WHEN** a live IP or scope query uses the helper and the transport fails
- **THEN** `LiveLookup` returns an error suitable for `crowdsecLapiFailureAction`

### Requirement: Alone-mode 401 retry preserves method and POST body
In alone mode, when an LAPI request receives HTTP 401, the helper SHALL renew the session token and retry once with the same HTTP method and the same request body bytes as the original attempt. Empty body still means GET; non-empty body means POST with replayed payload.

#### Scenario: Metrics POST survives 401 retry
- **WHEN** alone-mode metrics POST receives 401 then succeeds on retry after token renewal
- **THEN** the retry uses POST with the original metrics body
- **AND** metrics are accepted by LAPI

#### Scenario: 401 retry does not downgrade POST to GET
- **WHEN** alone-mode sends a POST with a non-empty body and receives 401
- **THEN** the retry MUST NOT send GET with an empty body

### Requirement: Stream-mode LAPI 401 is not retried
Stream and live GET paths that are not alone-mode login or metrics POST SHALL NOT apply the alone-mode 401 token renewal retry. A 401 on stream GET remains a single-attempt failure for that poll.

#### Scenario: Stream GET 401 single attempt
- **WHEN** stream mode receives HTTP 401 on `GET /v1/decisions/stream`
- **THEN** the helper does not recurse with token renewal for that request
