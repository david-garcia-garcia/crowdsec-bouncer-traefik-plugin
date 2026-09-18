## Purpose

Owns how a captcha provider siteverify request is posted (including `remoteip` from the already-resolved client address), how the response is classified as JSON, and whether a successful solve issues the gate cookie and redirect. Transport and JSON-decode failures re-render the challenge at 200. Cookie format stays on `core_plugin_middleware_captcha-gate`. Routing after the cookie stays on `core_plugin_middleware_captcha-routing`.

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
