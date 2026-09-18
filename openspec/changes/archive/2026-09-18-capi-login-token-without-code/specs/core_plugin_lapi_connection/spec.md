## ADDED Requirements

### Requirement: CAPI login stores a non-empty token after HTTP 2xx
After the CAPI `watchers/login` exchange returns HTTP 2xx, `getToken` SHALL store the login body's `token` on the stored transport when that string is non-empty. HTTP 2xx is already owned by `sendQuery`. JSON `code` MUST NOT be consulted as a success gate. When `token` is empty, `getToken` SHALL keep the existing `getToken statusCode:` error, including when JSON `code` is omitted (Go zero `0`). `Login` struct tags, expire parsing, CAPI host/route, 401 replay, and connection drain MUST NOT change.

#### Scenario: 2xx body with token and no JSON code
- **WHEN** CAPI login answers HTTP 2xx with body `{"token":"fresh","expire":"later"}` and no `code`
- **THEN** `getToken` returns nil
- **AND** the stored transport key is `fresh`

#### Scenario: 2xx body with empty token
- **WHEN** CAPI login answers HTTP 2xx with an empty `token`
- **THEN** `getToken` returns an error whose message starts with `getToken statusCode:`

#### Scenario: 2xx body with token and non-200 JSON code
- **WHEN** CAPI login answers HTTP 2xx with a non-empty `token` and a JSON `code` that is not 200
- **THEN** `getToken` stores that token on the stored transport
