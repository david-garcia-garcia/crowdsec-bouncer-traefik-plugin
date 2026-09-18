## Purpose

Owns how a captcha provider siteverify request is encoded, how the response is classified as JSON, and whether a successful solve issues the gate cookie and redirect. Cookie format stays on `core_plugin_middleware_captcha-gate`. Routing after the cookie stays on `core_plugin_middleware_captcha-routing`.

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
Siteverify SHALL include `remoteip` on both encodings only when Validate is given a non-empty client address. Dest today is `Validate` with the inbound request only and SHALL NOT invent that field. The address owner is `GetRemoteIP` / `clientRequest.remoteIP` already on the captcha challenge handler. Captcha MUST NOT re-parse forwarded headers.

#### Scenario: Dest Validate without address omits remoteip
- **WHEN** dest Validate receives only the inbound request
- **THEN** the siteverify body has `secret` and `response` and no `remoteip`

#### Scenario: Address on Validate includes remoteip when non-empty
- **WHEN** Validate is given a non-empty client address
- **THEN** both form and json siteverify bodies include `remoteip` with that address
