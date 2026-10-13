## ADDED Requirements

### Requirement: Unanswered AppSec challenge-prefix paths terminate
When AppSec is in use for this request (the bouncer subscribed to AppSec and the request is not SkipAppsec) and the URL path has prefix `/crowdsec-internal/challenge/`, and AppSec did not itself produce a response the bouncer is relaying or a ban the bouncer is writing, the bouncer SHALL write HTTP 404 and MUST NOT call `next`. A challenge, captcha, or ban envelope for that path SHALL still be written as today. Paths outside that prefix SHALL keep allow → `next`. Trusted IPs that already skip the bouncer before AppSec SHALL stay skipped. The bouncer MUST NOT add a new trusted-IP exception.

#### Scenario: AppSec allow on custom.js is 404
- **WHEN** AppSec is in use
- **AND** AppSec returns HTTP 200 with `{"action":"allow"}` for `GET /crowdsec-internal/challenge/custom.js`
- **THEN** the client status is 404
- **AND** `next` is not called

#### Scenario: Normal allow still calls next
- **WHEN** AppSec is in use
- **AND** AppSec returns HTTP 200 with `{"action":"allow"}` for a path outside `/crowdsec-internal/challenge/`
- **THEN** `next` is called

#### Scenario: Challenge envelope still relays
- **WHEN** AppSec returns a parseable `action` `challenge` with non-empty `user_body_content` for a path under `/crowdsec-internal/challenge/`
- **THEN** the client receives that envelope
- **AND** `next` is not called

## MODIFIED Requirements

### Requirement: Structured AppSec JSON is parsed on the AppSec client
`appsec.Client.Query` SHALL read a bounded AppSec response body (1 MiB) and, when the body is JSON with a non-empty `action`, return that structured result together with a nil error. Fields SHALL be `action`, `http_status`, `user_body_content`, `user_cookies`, and `user_headers`. An empty body or JSON without `action` on HTTP 200 SHALL pass (nil error; the result is an allow action). HTTP 500 and unreachable SHALL honor `bouncerAppsecFailureAction` (`passthrough` | `ban` | `captcha`) instead of `FailureBlock` / `UnreachableBlock`. The response body SHALL be drained so the AppSec HTTP client can reuse the connection. Allow or empty 200 MUST NOT call `next` when the URL path has prefix `/crowdsec-internal/challenge/` (`Unanswered AppSec challenge-prefix paths terminate`).

#### Scenario: Allow JSON passes
- **WHEN** AppSec returns HTTP 200 with `{"action":"allow"}`
- **AND** the URL path is not under `/crowdsec-internal/challenge/`
- **THEN** `Query` returns a nil error and the request proceeds to `next`

#### Scenario: Empty 200 still passes
- **WHEN** AppSec returns HTTP 200 with an empty body
- **AND** the URL path is not under `/crowdsec-internal/challenge/`
- **THEN** `Query` returns a nil error and the request proceeds to `next`
