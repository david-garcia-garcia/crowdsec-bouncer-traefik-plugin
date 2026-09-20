## Purpose

Lets an earlier Traefik middleware force this bouncer to ban or captcha a client through a config-named request header, without consulting CrowdSec stream or live lookup, while still honoring an already-passed captcha gate.

## ADDED Requirements

### Requirement: Empty crowdsecDecisionHeader leaves lookup unchanged
When `crowdsecDecisionHeader` is empty or whitespace-only, the middleware MUST NOT read any default header name as a forced decision. ServeHTTP SHALL continue with today's trusted-IP skip, mode dispatcher, and stream/live lookup.

#### Scenario: Feature off ignores X-Crowdsec-Decision
- **WHEN** `crowdsecDecisionHeader` is empty
- **AND** the request has header `X-Crowdsec-Decision: c`
- **THEN** the middleware does not apply captcha from that header
- **AND** it continues with stream or live lookup as today

### Requirement: Configured header b or c skips stream and live lookup
When `crowdsecDecisionHeader` names a request header, and that header's first value after trim is exactly `b` or exactly `c`, the middleware SHALL apply ban (`b`) or captcha (`c`) without querying the stream cache or live LAPI. It SHALL reuse the client address `GetRemoteIP` already chose. It MUST NOT treat the decision header as an address, identity scope, or AppSec action. Trusted clients SHALL still skip the whole middleware, including this header.

#### Scenario: Header c captchas without stream lookup
- **WHEN** `crowdsecDecisionHeader` is `X-Crowdsec-Decision`
- **AND** a non-trusted client sends `X-Crowdsec-Decision: c`
- **AND** the captcha gate cookie is absent or invalid
- **THEN** the response is the captcha challenge
- **AND** the middleware does not query stream or live LAPI for that request

#### Scenario: Header b bans without stream lookup
- **WHEN** `crowdsecDecisionHeader` is `X-Crowdsec-Decision`
- **AND** a non-trusted client sends `X-Crowdsec-Decision: b`
- **THEN** the response is the ban page
- **AND** the middleware does not query stream or live LAPI for that request

#### Scenario: Trusted client still skips the force header
- **WHEN** `crowdsecDecisionHeader` is `X-Crowdsec-Decision`
- **AND** the client address is in `clientTrustedIps`
- **AND** the request has `X-Crowdsec-Decision: b`
- **THEN** the request reaches the next handler
- **AND** the middleware does not apply ban from that header

### Requirement: Other header values are ignored
A missing header, empty value, or any token other than exact trimmed `b` or `c` (including `t`, `B`, `ban`, `captcha`) SHALL leave lookup unchanged. `New` MUST NOT fail because the header name is set.

#### Scenario: Unknown token continues lookup
- **WHEN** `crowdsecDecisionHeader` is `X-Crowdsec-Decision`
- **AND** the request has `X-Crowdsec-Decision: t`
- **THEN** the middleware does not apply ban from that header
- **AND** it continues with stream or live lookup as today

### Requirement: Forced captcha still honors the gate cookie
When the forced header is `c` and the request already carries a valid captcha gate cookie for this client address, the middleware SHALL pass the request to the next handler (AppSec on pass still runs when enabled) even though the header is still `c`. A forced `b` SHALL not consult the captcha gate.

#### Scenario: Gated visitor passes with header still c
- **WHEN** `crowdsecDecisionHeader` is `X-Crowdsec-Decision`
- **AND** a non-trusted client sends `X-Crowdsec-Decision: c`
- **AND** `Check` is true for that request and client address
- **AND** the request is not a captcha-form POST
- **THEN** the request reaches the next handler
- **AND** the middleware does not show the captcha challenge
