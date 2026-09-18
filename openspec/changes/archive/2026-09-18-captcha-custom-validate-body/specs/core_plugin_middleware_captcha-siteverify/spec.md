## ADDED Requirements

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
