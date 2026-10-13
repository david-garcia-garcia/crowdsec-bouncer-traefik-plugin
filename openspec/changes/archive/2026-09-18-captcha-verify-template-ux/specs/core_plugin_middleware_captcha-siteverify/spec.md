## ADDED Requirements

### Requirement: Siteverify POST includes remoteip from the resolved client address

When the captcha challenge handler posts a solver token to the provider validate URL, the form SHALL include `secret`, `response`, and `remoteip`. `remoteip` SHALL be the `remoteIP` string already passed into that handler, which is `clientRequest.remoteIP` after `GetRemoteIP` succeeded and `ipAddr.String()` was written. The captcha package MUST NOT parse `X-Forwarded-For`, `X-Real-Ip`, or `RemoteAddr` to produce this field. Custom provider uses the same three fields. The plugin MUST NOT send hCaptcha `sitekey` or Turnstile `idempotency_key`.

#### Scenario: Siteverify form includes remoteip

- **WHEN** a solver POST reaches siteverify
- **AND** the challenge handler was called with a resolved `remoteIP`
- **THEN** the provider request body includes `secret`, `response`, and `remoteip`
- **AND** `remoteip` equals that resolved `remoteIP`

#### Scenario: Captcha does not re-parse forwarded headers

- **WHEN** a solver POST reaches siteverify
- **THEN** captcha does not read `X-Forwarded-For`, `X-Real-Ip`, or `RemoteAddr` to build `remoteip`

### Requirement: Transport and JSON decode failures re-render the challenge

When siteverify transport fails or JSON decode fails, `Validate` SHALL return `(false, err)` so the failure stays classified. The challenge handler SHALL log the error and SHALL write the captcha HTML at HTTP 200. It MUST NOT write HTTP 400. Empty token, `success:false`, and a non-JSON Content-Type SHALL stay `(false, nil)` and the same 200 challenge. Siteverify HTTP status on a received body is out of scope. Cookie format stays on `core_plugin_middleware_captcha-gate`.

#### Scenario: Transport error re-renders challenge at 200

- **WHEN** a solver POST reaches siteverify
- **AND** the provider request fails to send
- **THEN** the solver receives the captcha challenge at 200
- **AND** no `crowdsec_captcha_gate` cookie is set
- **AND** the response is not HTTP 400

#### Scenario: JSON decode error re-renders challenge at 200

- **WHEN** a solver POST reaches siteverify
- **AND** the provider responds with Siteverify JSON Content-Type and a body that is not JSON
- **THEN** the solver receives the captcha challenge at 200
- **AND** no `crowdsec_captcha_gate` cookie is set
- **AND** the response is not HTTP 400

#### Scenario: Empty token and success false stay 200 challenge

- **WHEN** a solver POST has an empty token, or siteverify JSON has `success` false, or Content-Type is not `application/json`
- **THEN** the solver receives the captcha challenge at 200
- **AND** no `crowdsec_captcha_gate` cookie is set
