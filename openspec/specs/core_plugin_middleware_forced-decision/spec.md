## Purpose

Lets an earlier Traefik middleware force this bouncer to ban or captcha a client through a config-named request header. Ban skips stream and live lookup. Captcha still consults that lookup so an existing ban wins, then reuses the captcha gate.

## Requirements

### Requirement: Empty bouncerDecisionHeader leaves lookup unchanged
When `bouncerDecisionHeader` is empty or whitespace-only, the middleware MUST NOT read any default header name as a forced decision. ServeHTTP SHALL continue with today's trusted-IP skip, mode dispatcher, and stream/live lookup.

#### Scenario: Feature off ignores X-Crowdsec-Decision
- **WHEN** `bouncerDecisionHeader` is empty
- **AND** the request has header `X-Crowdsec-Decision: c`
- **THEN** the middleware does not apply captcha from that header
- **AND** it continues with stream or live lookup as today

### Requirement: Configured header b skips stream and live lookup
When `bouncerDecisionHeader` names a request header, and that header's first value after trim is exactly `b`, the middleware SHALL apply ban without querying the stream cache or live LAPI. It SHALL reuse the client address `GetRemoteIP` already chose. It MUST NOT treat the decision header as an address, identity scope, or AppSec action. Trusted clients SHALL still skip the whole middleware, including this header.

#### Scenario: Header b bans without stream lookup
- **WHEN** `bouncerDecisionHeader` is `X-Crowdsec-Decision`
- **AND** a non-trusted client sends `X-Crowdsec-Decision: b`
- **THEN** the response is the ban page
- **AND** the middleware does not query stream or live LAPI for that request

#### Scenario: Trusted client still skips the force header
- **WHEN** `bouncerDecisionHeader` is `X-Crowdsec-Decision`
- **AND** the client address is in `bouncerClientTrustedIps`
- **AND** the request has `X-Crowdsec-Decision: b`
- **THEN** the request reaches the next handler
- **AND** the middleware does not apply ban from that header

### Requirement: Header c does not override an internal ban
When the configured header's trimmed value is exactly `c`, the middleware SHALL still consult stream or live lookup. When that lookup (or a fail-closed / failure-action ban) is ban, the middleware SHALL apply that ban and SHALL log a WARN whose message stem is `ServeHTTP:forcedCaptchaSuperseded`. When lookup is not ban, the middleware SHALL apply captcha without requiring a CrowdSec captcha decision.

#### Scenario: Header c captchas when lookup is not ban
- **WHEN** `bouncerDecisionHeader` is `X-Crowdsec-Decision`
- **AND** a non-trusted client sends `X-Crowdsec-Decision: c`
- **AND** stream or live lookup is not ban
- **AND** the captcha gate cookie is absent or invalid
- **THEN** the response is the captcha challenge

#### Scenario: Header c loses to a stream ban
- **WHEN** `bouncerDecisionHeader` is `X-Crowdsec-Decision`
- **AND** a non-trusted client sends `X-Crowdsec-Decision: c`
- **AND** stream lookup is ban for that client
- **THEN** the response is the ban page
- **AND** the log includes WARN `ServeHTTP:forcedCaptchaSuperseded`

### Requirement: Other header values are ignored
A missing header, empty value, or any token other than exact trimmed `b` or `c` (including `t`, `B`, `ban`, `captcha`) SHALL leave lookup unchanged. `New` MUST NOT fail because the header name is set.

#### Scenario: Unknown token continues lookup
- **WHEN** `bouncerDecisionHeader` is `X-Crowdsec-Decision`
- **AND** the request has `X-Crowdsec-Decision: t`
- **THEN** the middleware does not apply ban from that header
- **AND** it continues with stream or live lookup as today

### Requirement: Forced captcha still honors the gate cookie
When the forced header is `c`, lookup is not ban, and the request already carries a valid captcha gate cookie for this client address, the middleware SHALL pass the request to the next handler (AppSec on pass still runs when enabled) even though the header is still `c`. A forced `b` SHALL not consult the captcha gate.

#### Scenario: Gated visitor passes with header still c
- **WHEN** `bouncerDecisionHeader` is `X-Crowdsec-Decision`
- **AND** a non-trusted client sends `X-Crowdsec-Decision: c`
- **AND** stream or live lookup is not ban
- **AND** `Check` is true for that request and client address
- **AND** the request is not a captcha-form POST
- **THEN** the request reaches the next handler
- **AND** the middleware does not show the captcha challenge
