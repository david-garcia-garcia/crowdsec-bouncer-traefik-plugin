## Purpose

Owns how a eucaptcha solver token is posted to EU CAPTCHA `/v1/verify` and classified as pass, reject, or error from `success` and `train`. Siteverify encoding stays on `core_plugin_middleware_captcha-siteverify`. Assessments stay on `core_plugin_middleware_captcha-assessments`. Gate cookie format stays on `core_plugin_middleware_captcha-gate`. Widget pairing stays on `core_plugin_middleware_captcha-widget`.

## Requirements

### Requirement: Eucaptcha verify POST uses the official verify URL and JSON fields
When the captcha provider is `eucaptcha` and a solver token is posted, the captcha challenge handler SHALL POST JSON to `https://api.eu-captcha.eu/v1/verify`. The request `Content-Type` SHALL be `application/json`. The JSON object SHALL include `sitekey` (configured site key), `secret` (configured secret), `client_ip` (the client address already passed into `Validate`), `client_token` (the posted solver token), and `client_user_agent` (the request User-Agent already passed into `Pass`). The request SHALL use the captcha client's existing HTTP client and `captchaSiteverifyHTTPTimeoutSeconds`. The plugin MUST NOT log the secret.

#### Scenario: Verify URL is api.eu-captcha.eu /v1/verify
- **WHEN** the provider is `eucaptcha` and a solver POST has a non-empty token
- **AND** the client address passed into `Validate` is non-empty
- **THEN** the provider request URL is `https://api.eu-captcha.eu/v1/verify`
- **AND** the request `Content-Type` is `application/json`

#### Scenario: JSON body has the five necessary fields
- **WHEN** a solver POST reaches eucaptcha verify
- **AND** the client address passed into `Validate` is non-empty
- **THEN** the JSON object has `sitekey` equal to the configured site key
- **AND** `secret` equal to the configured secret
- **AND** `client_token` equal to the posted token
- **AND** `client_ip` equal to that address
- **AND** `client_user_agent` equal to the User-Agent passed into `Pass`

### Requirement: Eucaptcha verify reuses GetRemoteIP and the request User-Agent
`client_ip` SHALL be the `remoteIP` string already passed into `Validate`, which is `clientRequest.remoteIP` after `GetRemoteIP` succeeded and `ipAddr.String()` was written. `client_user_agent` SHALL be `r.UserAgent()` on the challenge request. The captcha package MUST NOT parse `X-Forwarded-For`, `X-Real-Ip`, `X-Client-IP`, or `RemoteAddr` to produce `client_ip`. The captcha package MUST NOT send the LAPI plugin User-Agent. User-Agent MUST NOT be stored on `clientRequest`. When `remoteIP` is empty, this verifier SHALL return Pass-false with no error and MUST NOT POST verify. When `userAgent` is empty, this verifier SHALL still POST and SHALL send `client_user_agent` as the empty string.

#### Scenario: Non-empty remoteIP is client_ip
- **WHEN** a solver POST reaches eucaptcha verify
- **AND** the challenge handler was called with a non-empty `remoteIP`
- **THEN** `client_ip` equals that `remoteIP`

#### Scenario: Empty remoteIP rejects without a vendor POST
- **WHEN** a solver POST has a non-empty token
- **AND** `Validate` is given an empty client address
- **THEN** the plugin does not POST `https://api.eu-captcha.eu/v1/verify`
- **AND** `Validate` returns `Reject`

#### Scenario: Empty User-Agent is forwarded
- **WHEN** a solver POST reaches eucaptcha verify
- **AND** the challenge request `User-Agent` is empty
- **AND** the client address passed into `Validate` is non-empty
- **THEN** the JSON object has `client_user_agent` equal to the empty string
- **AND** the plugin still POSTs verify

#### Scenario: Captcha does not re-parse forwarded headers
- **WHEN** a solver POST reaches eucaptcha verify
- **THEN** captcha does not read `X-Forwarded-For`, `X-Real-Ip`, `X-Client-IP`, or `RemoteAddr` to build `client_ip`

### Requirement: Eucaptcha pass is success true and train false or null
A successful eucaptcha HTTP 200 JSON body SHALL pass only when `success` is true and `train` is JSON false or JSON null. An omitted `train` key SHALL be treated the same as JSON null (pass when `success` is true). `train` JSON true SHALL be Pass-false even when `success` is true. `success` false SHALL be Pass-false.

#### Scenario: success true and train false passes
- **WHEN** eucaptcha verify returns HTTP 200 and body `{"success": true, "train": false}`
- **THEN** the solver token passes

#### Scenario: success true and train null passes
- **WHEN** eucaptcha verify returns HTTP 200 and body `{"success": true, "train": null}`
- **THEN** the solver token passes

#### Scenario: success true and omitted train passes
- **WHEN** eucaptcha verify returns HTTP 200 and body `{"success": true}`
- **THEN** the solver token passes

#### Scenario: train true rejects even when success is true
- **WHEN** eucaptcha verify returns HTTP 200 and body `{"success": true, "train": true}`
- **THEN** the solver token is rejected
- **AND** no `crowdsec_captcha_gate` cookie is set

#### Scenario: success false rejects
- **WHEN** eucaptcha verify returns HTTP 200 and body `{"success": false, "train": false}`
- **THEN** the solver token is rejected
- **AND** no `crowdsec_captcha_gate` cookie is set

### Requirement: Eucaptcha classify Error versus Reject
A non-2xx eucaptcha response or a missing or undecodable JSON body SHALL be an error outcome, not a reject. HTTP 200 JSON with `success` false or `train` true SHALL be a reject. The challenge handler SHALL log an error outcome and SHALL write the captcha HTML at HTTP 200 with the boot script. It MUST NOT write HTTP 400.

#### Scenario: Non-2xx is error
- **WHEN** eucaptcha verify returns a non-2xx status
- **THEN** the challenge handler treats the result as an error
- **AND** the solver receives the captcha challenge at 200
- **AND** no `crowdsec_captcha_gate` cookie is set
- **AND** the response is not HTTP 400

#### Scenario: Missing or undecodable JSON body is error
- **WHEN** eucaptcha verify returns HTTP 200 with an empty body or a body that is not JSON
- **THEN** the challenge handler treats the result as an error
- **AND** the solver receives the captcha challenge at 200
- **AND** no `crowdsec_captcha_gate` cookie is set
- **AND** the response is not HTTP 400

#### Scenario: train true is reject not error
- **WHEN** eucaptcha verify returns HTTP 200 and body `{"success": true, "train": true}`
- **THEN** the solver token is rejected
- **AND** the outcome is not an error
