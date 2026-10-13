## Purpose

Owns how a recaptcha-enterprise solver token is posted to Google Cloud assessments and classified as pass, reject, or error. Siteverify encoding stays on `core_plugin_middleware_captcha-siteverify`. Gate cookie format stays on `core_plugin_middleware_captcha-gate`.

## Requirements

### Requirement: Assessments POST uses the Cloud assessments URL and header API key
When the captcha provider is `recaptcha-enterprise` and a solver token is posted, the captcha challenge handler SHALL POST JSON to `https://recaptchaenterprise.googleapis.com/v1/projects/{project}/assessments` where `{project}` is the configured project id. The Cloud API key SHALL be sent as the `X-Goog-Api-Key` header. The handler MUST NOT put the API key in the query string and MUST NOT log the API key. The request SHALL use the captcha client's existing HTTP client and `captchaSiteverifyHTTPTimeoutSeconds`. The plugin MUST NOT add a Google client library.

#### Scenario: Assessments URL includes the project id
- **WHEN** the provider is `recaptcha-enterprise` and a solver POST has a non-empty token
- **AND** the configured project id is `my-project`
- **THEN** the provider request URL is `https://recaptchaenterprise.googleapis.com/v1/projects/my-project/assessments`

#### Scenario: API key is the X-Goog-Api-Key header
- **WHEN** a solver POST reaches assessments
- **THEN** the request has header `X-Goog-Api-Key` equal to the configured Cloud API key
- **AND** the request URL has no `key` query parameter

### Requirement: Assessments event fields and client address owner
The assessments JSON body SHALL include `event.token` (the posted solver token) and `event.siteKey` (the configured site key). `event.userIpAddress` SHALL be included only when the client address passed into the challenge handler is non-empty. That address SHALL be `clientRequest.remoteIP` after `GetRemoteIP`. The captcha package MUST NOT parse `X-Forwarded-For`, `X-Real-Ip`, or `RemoteAddr` to produce this field. `event.expectedAction` SHALL be included only when a non-empty action is configured.

#### Scenario: Token and site key are always sent
- **WHEN** a solver POST reaches assessments
- **THEN** the JSON body has `event.token` equal to the posted token
- **AND** `event.siteKey` equal to the configured site key

#### Scenario: Non-empty remoteIP is userIpAddress
- **WHEN** a solver POST reaches assessments
- **AND** the challenge handler was called with a non-empty `remoteIP`
- **THEN** `event.userIpAddress` equals that `remoteIP`

#### Scenario: Empty remoteIP omits userIpAddress
- **WHEN** a solver POST reaches assessments
- **AND** the challenge handler was called with an empty `remoteIP`
- **THEN** the JSON body has no `event.userIpAddress`

#### Scenario: Empty action omits expectedAction
- **WHEN** a solver POST reaches assessments
- **AND** the configured action is empty after trim
- **THEN** the JSON body has no `event.expectedAction`

#### Scenario: Captcha does not re-parse forwarded headers
- **WHEN** a solver POST reaches assessments
- **THEN** captcha does not read `X-Forwarded-For`, `X-Real-Ip`, or `RemoteAddr` to build `event.userIpAddress`

### Requirement: Assessments pass order is valid then action then score
A successful assessments HTTP response with an Assessment body SHALL pass only when, in this order: `tokenProperties.valid` is true; when an action is configured, `tokenProperties.action` equals that action case-insensitively; when a minimum score is configured, `riskAnalysis.score` is at least that minimum. A checkbox key with no action and no minimum SHALL pass on `valid` alone. `riskAnalysis.score` is a JSON number in `0.0`–`1.0`.

#### Scenario: Valid checkbox with no action or minimum passes
- **WHEN** assessments returns an Assessment with `tokenProperties.valid` true
- **AND** no action and no minimum score are configured
- **THEN** the solver token passes

#### Scenario: Action matches case-insensitively
- **WHEN** assessments returns `tokenProperties.valid` true and `tokenProperties.action` `login`
- **AND** the configured action is `LOGIN`
- **THEN** the solver token passes

#### Scenario: Different action rejects
- **WHEN** assessments returns `tokenProperties.valid` true and `tokenProperties.action` `checkout`
- **AND** the configured action is `login`
- **THEN** the solver token is rejected

#### Scenario: Score below minimum rejects
- **WHEN** assessments returns `tokenProperties.valid` true and `riskAnalysis.score` `0.3`
- **AND** the configured minimum score is `0.5`
- **THEN** the solver token is rejected

#### Scenario: Score at minimum passes
- **WHEN** assessments returns `tokenProperties.valid` true and `riskAnalysis.score` `0.5`
- **AND** the configured minimum score is `0.5`
- **THEN** the solver token passes

### Requirement: Assessments classify Error versus Reject
A non-2xx assessments response, a missing or non-JSON body, or a Google error envelope without `tokenProperties` SHALL be an error outcome, not a reject. A successful Assessment with `tokenProperties.valid` false SHALL be a reject. The plugin MUST NOT treat a Google error envelope as a reject.

#### Scenario: valid false is reject
- **WHEN** assessments returns HTTP 2xx and an Assessment with `tokenProperties.valid` false
- **THEN** the solver token is rejected
- **AND** the outcome is not an error

#### Scenario: Non-2xx is error
- **WHEN** assessments returns a non-2xx status
- **THEN** the challenge handler treats the result as an error
- **AND** the solver receives the captcha challenge at 200
- **AND** no `crowdsec_captcha_gate` cookie is set

#### Scenario: Missing or non-JSON body is error
- **WHEN** assessments returns HTTP 2xx with an empty body or a body that is not JSON
- **THEN** the challenge handler treats the result as an error
- **AND** the solver receives the captcha challenge at 200
- **AND** no `crowdsec_captcha_gate` cookie is set
