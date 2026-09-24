## MODIFIED Requirements

### Requirement: Transport and JSON decode failures re-render the challenge
When siteverify transport fails or JSON decode fails, the siteverify verifier SHALL return `(false, err)` and `Validate` SHALL surface that error return so the failure stays classified. The challenge handler SHALL log the error and SHALL write the captcha HTML at HTTP 200 with the boot script. It MUST NOT write HTTP 400. Empty token SHALL be `Validate` `None` and MUST NOT POST siteverify. `success:false` and a non-JSON Content-Type SHALL stay verifier Pass-false with no error and the same 200 challenge with boot. Siteverify HTTP status on a received body is out of scope. Cookie format stays on `core_plugin_middleware_captcha-gate`. Outcome names stay on `core_plugin_middleware_captcha-widget`.

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

#### Scenario: Empty token does not POST siteverify
- **WHEN** the request is not a POST or the token field is empty
- **THEN** the plugin does not POST siteverify
- **AND** `Validate` returns `None`
