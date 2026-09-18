## Purpose

Owns whether a received captcha siteverify HTTP response is eligible to count as a successful provider verify. Cookie mint and first-solve 302 after success stay on `core_plugin_middleware_captcha-gate`.

## Requirements

### Requirement: 2xx is required before reading success
When a siteverify HTTP response is received, the plugin SHALL treat only status codes 200 through 299 inclusive as eligible to inspect Content-Type or decode JSON `success`. The status check SHALL run before Content-Type matching and before decoding the body. After a 2xx status, dest Content-Type prefix `application/json` and decoded `success` SHALL still decide the verify. This rule SHALL apply to every configured provider, including custom.

#### Scenario: HTTP 500 with success JSON is not a solve
- **WHEN** siteverify answers status `500`
- **AND** `Content-Type` is `application/json`
- **AND** the body is `{"success":true}`
- **THEN** the verify is failed
- **AND** cookie `crowdsec_captcha_gate` is not set
- **AND** the response is not `302 Found`

#### Scenario: Status 201 with success JSON is a solve
- **WHEN** siteverify answers status `201`
- **AND** `Content-Type` is `application/json`
- **AND** the body is `{"success":true}`
- **THEN** the verify is successful
- **AND** the captcha challenge handler sets `crowdsec_captcha_gate` and redirects `302 Found`

#### Scenario: Status 200 with success JSON remains a solve
- **WHEN** siteverify answers status `200`
- **AND** `Content-Type` is `application/json`
- **AND** the body is `{"success":true}`
- **THEN** the verify is successful

### Requirement: Non-2xx is a failed verify, not an error
A received siteverify status outside 200–299 SHALL be a failed verify: the challenge handler MUST NOT receive an error from that status. The handler SHALL re-render the captcha challenge at `200`. Transport errors with no response, and JSON decode errors after a 2xx body, SHALL keep their existing error returns. A named test SHALL assert the HTTP 500 plus JSON `success: true` path.

#### Scenario: Non-2xx re-renders the challenge
- **WHEN** a captcha-form POST is verified
- **AND** siteverify answers status `500` with `Content-Type: application/json` and body `{"success":true}`
- **THEN** the client receives `200` and the captcha challenge page
- **AND** cookie `crowdsec_captcha_gate` is not set
- **AND** the response is not `302 Found`
