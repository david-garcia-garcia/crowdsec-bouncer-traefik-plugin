## Purpose

Owns how a captcha provider siteverify request is encoded (form or custom JSON) and posted (including `remoteip` from the already-resolved client address when non-empty), how the response is classified as JSON, and whether a successful solve issues the gate cookie and redirect. Transport and JSON-decode failures re-render the challenge at 200. Cookie format stays on `core_plugin_middleware_captcha-gate`. Routing after the cookie stays on `core_plugin_middleware_captcha-routing`.

## Requirements

### Requirement: Siteverify JSON is the media type before parameters

The plugin SHALL treat a provider siteverify response as JSON when the `Content-Type` media type before parameters equals `application/json` case-insensitively. A missing `Content-Type` or a media type that is not `application/json` SHALL NOT be treated as JSON. The plugin MUST NOT require the header to be lowercase and MUST NOT treat a leading substring such as `application/jsonp` as JSON.

#### Scenario: Mixed-case JSON Content-Type is accepted

- **WHEN** a solver POST reaches siteverify
- **AND** the provider responds with `Content-Type: Application/JSON` and body `{"success":true}`
- **THEN** the plugin treats the body as JSON

#### Scenario: JSON Content-Type with a parameter is accepted

- **WHEN** a solver POST reaches siteverify
- **AND** the provider responds with `Content-Type: application/json; charset=utf-8` and a JSON body
- **THEN** the plugin treats the body as JSON

#### Scenario: Missing or non-JSON Content-Type is not JSON

- **WHEN** a solver POST reaches siteverify
- **AND** the provider omits `Content-Type` or returns a media type other than `application/json`
- **THEN** the plugin does not treat the body as JSON
- **AND** the solver receives the captcha challenge at 200 with no `crowdsec_captcha_gate` cookie

### Requirement: Successful JSON siteverify issues gate cookie and redirect

When siteverify is JSON and the decoded body has `success` true, the captcha challenge handler SHALL set cookie `crowdsec_captcha_gate` and respond `302 Found` to the request URL. That outcome SHALL match the existing lowercase `application/json` path. Cookie format stays on `core_plugin_middleware_captcha-gate`.

#### Scenario: Mixed-case JSON success issues cookie and 302

- **WHEN** a solver POST reaches siteverify
- **AND** the provider responds with `Content-Type: Application/JSON` and body `{"success":true}`
- **THEN** the response status is 302
- **AND** the response sets `crowdsec_captcha_gate`

### Requirement: Siteverify POST includes remoteip from the resolved client address

When the captcha challenge handler posts a solver token to the provider validate URL, the siteverify body SHALL include `secret`, `response`, and `remoteip`. `remoteip` SHALL be the `remoteIP` string already passed into that handler, which is `clientRequest.remoteIP` after `GetRemoteIP` succeeded and `ipAddr.String()` was written. The captcha package MUST NOT parse `X-Forwarded-For`, `X-Real-Ip`, or `RemoteAddr` to produce this field. Form and custom JSON encodings use the same three fields. The plugin MUST NOT send hCaptcha `sitekey` or Turnstile `idempotency_key`.

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

### Requirement: Custom siteverify request body encoding
When the captcha provider is `custom` and `captchaCustomValidateBody` is `json`, siteverify SHALL POST `application/json` whose object has `secret` and `response` (the solver token) to the configured validate URL. When that knob is empty or `form`, or the provider is hcaptcha, recaptcha, or turnstile, siteverify SHALL POST `application/x-www-form-urlencoded` `secret` and `response` the same way dest does today. Extra verify fields and headers stay out of scope except absorb-only `remoteip`. Reply classification, gate cookie, and 302 stay on the existing requirements in this spec.

#### Scenario: Custom json posts JSON secret and response
- **WHEN** the provider is `custom` and `captchaCustomValidateBody` is `json`
- **AND** a solver POST reaches siteverify
- **THEN** the provider request `Content-Type` is `application/json`
- **AND** the JSON object has `secret` and `response`

#### Scenario: Custom form or omit stays urlencoded
- **WHEN** the provider is `custom` and `captchaCustomValidateBody` is empty or `form`
- **AND** a solver POST reaches siteverify
- **THEN** the provider request is `application/x-www-form-urlencoded` with `secret` and `response`

#### Scenario: Built-in always urlencoded
- **WHEN** the provider is hcaptcha, recaptcha, or turnstile
- **AND** a solver POST reaches siteverify
- **THEN** the provider request is `application/x-www-form-urlencoded` with `secret` and `response`

#### Scenario: Custom json success still issues cookie and 302
- **WHEN** the provider is `custom` and `captchaCustomValidateBody` is `json`
- **AND** the provider responds with Siteverify JSON and `success` true
- **THEN** the response status is 302
- **AND** the response sets `crowdsec_captcha_gate`

### Requirement: Siteverify remoteip only when Validate is given an address
Siteverify SHALL include `remoteip` on both encodings only when Validate is given a non-empty client address. `Validate(r, remoteIP)` SHALL NOT invent that field when `remoteIP` is empty. The address owner is `GetRemoteIP` / `clientRequest.remoteIP` already on the captcha challenge handler. Captcha MUST NOT re-parse forwarded headers.

#### Scenario: Validate with empty address omits remoteip
- **WHEN** Validate is given an empty client address
- **THEN** the siteverify body has `secret` and `response` and no `remoteip`

#### Scenario: Address on Validate includes remoteip when non-empty
- **WHEN** Validate is given a non-empty client address
- **THEN** both form and json siteverify bodies include `remoteip` with that address
