## MODIFIED Requirements

### Requirement: Unanswered AppSec challenge-prefix paths terminate
When AppSec is in use for this request (the bouncer subscribed to AppSec; an action rule cannot skip AppSec on this prefix, see "Action rules cannot skip AppSec on the challenge prefix") and the URL path has prefix `/crowdsec-internal/challenge/`, and neither AppSec nor the router captcha gate wrote a response, the bouncer SHALL write HTTP 404 and MUST NOT call `next`. A challenge, captcha, or ban envelope for that path SHALL still be written as today. Paths outside that prefix SHALL keep allow → `next`. Trusted IPs that already skip the bouncer before AppSec SHALL stay skipped. The bouncer MUST NOT add a new trusted-IP exception.

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

#### Scenario: Captcha-form POST the gate passes on a challenge path is 404
- **WHEN** AppSec allows a POST carrying `crowdsec_captcha_challenge=v1` to a path under `/crowdsec-internal/challenge/`
- **AND** the router captcha gate does not write a response for it (no usable captcha, or the path is a widget asset)
- **THEN** the client status is 404
- **AND** `next` is not called

#### Scenario: Solved captcha action rule on a challenge path is 404
- **WHEN** a captcha action rule matches a path under `/crowdsec-internal/challenge/`
- **AND** AppSec allows the request and the visitor already holds a valid captcha gate cookie
- **THEN** the client status is 404
- **AND** `next` is not called

## ADDED Requirements

### Requirement: Action rules cannot skip AppSec on the challenge prefix
When a matching `bypass` or `bypassAppsec` action rule would skip AppSec and the URL path has prefix `/crowdsec-internal/challenge/`, the bouncer SHALL NOT skip AppSec for that request: CrowdSec, not the site, owns that prefix, and the challenge cannot be solved unless AppSec answers its scripts and submit. A LAPI skip from the same rows SHALL stay. The bouncer SHALL log TRACE `foldActionRules` with attr `challengePathKeepsAppsec`. Upstream: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/393, https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/413.

#### Scenario: Static-asset bypass rule still queries AppSec for a challenge script
- **WHEN** `bouncerActionRules` contains `{name: static, path: "\.js$", action: [bypass]}`
- **AND** the request is `GET /crowdsec-internal/challenge/fpscanner.js`
- **THEN** AppSec `Query` runs for that request
- **AND** the LAPI leg is still skipped

#### Scenario: Bypass rule on an allowed challenge path is 404
- **WHEN** `bouncerActionRules` contains `{name: appsec, path: "^/crowdsec-internal/challenge/", action: [bypassAppsec]}`
- **AND** AppSec returns HTTP 200 with `{"action":"allow"}` for `GET /crowdsec-internal/challenge/custom.js`
- **THEN** the client status is 404
- **AND** `next` is not called
