## Purpose

Owns how `handleRemediationServeHTTP` routes captcha-kind requests after the gate cookie and first-solve 302: solved-form POST redirect, exact-path custom challenge-resource passthrough, and HEAD on the captcha path. Cookie grace stays on `core_plugin_middleware_captcha-gate`.

## Requirements

### Requirement: Captcha-kind routing includes HEAD
When captcha is configured and the remediation kind is captcha, the remediation handler SHALL apply captcha routing for every HTTP method, including HEAD. It MUST NOT exclude HEAD from the captcha branch. Ban kind SHALL stay on the ban path.

#### Scenario: Captcha HEAD is not ban
- **WHEN** captcha is configured
- **AND** the request method is HEAD
- **AND** the remediation kind is captcha
- **AND** the path is not a configured custom challenge resource
- **AND** `Check` is false
- **THEN** the handler serves the captcha challenge path
- **AND** it MUST NOT fall through to ban

#### Scenario: Ban HEAD stays ban
- **WHEN** the remediation kind is ban
- **AND** the request method is HEAD
- **THEN** the handler applies ban
- **AND** captcha routing MUST NOT run

### Requirement: Solved captcha-form POST does not reach origin
When captcha kind applies and `Check` is true, a captcha-form POST SHALL receive `302 Found` to the same request URL. The handler MUST NOT forward that POST to origin. Detection SHALL reuse the existing provider-response reader (query / POST form / raw body, body restored). A GET that only carries the provider field in the query is not a form POST. An ordinary POST that does not carry the provider response field SHALL still reach origin after `Check` is true.

#### Scenario: Duplicate-tab form POST redirects
- **WHEN** captcha kind applies
- **AND** `Check` is true
- **AND** the request is POST
- **AND** the provider response field is non-empty
- **THEN** the response is `302 Found` to the same URL
- **AND** origin MUST NOT receive the POST

#### Scenario: Ordinary POST after solve reaches origin
- **WHEN** captcha kind applies
- **AND** `Check` is true
- **AND** the request is POST
- **AND** the provider response field is empty
- **THEN** the request is passed to origin (AppSec still runs when enabled)

### Requirement: Solved-form redirect does not remint or re-verify
The Check-true form-POST redirect SHALL set the configured remediation header to `solved-captcha` when that header name is configured. It MUST NOT remint the gate cookie. It MUST NOT call the captcha provider. First-solve cookie mint and 302 stay on the captcha challenge handler.

#### Scenario: Check-true form POST keeps the existing cookie
- **WHEN** a captcha-form POST is redirected because `Check` is true
- **THEN** the response is `302 Found`
- **AND** no new gate cookie is issued
- **AND** the provider siteverify endpoint is not called

### Requirement: Custom challenge resources pass to origin under captcha only
While the remediation kind is captcha, a request whose path is an exact match of a configured browser challenge-resource path SHALL pass to origin. Ban kind MUST NOT pass those paths. Passthrough SHALL use the same pass path as other allowed requests so AppSec still runs when enabled. Built-in provider CDN URLs are not a match set.

#### Scenario: Custom JS path under captcha reaches origin
- **WHEN** captcha kind applies
- **AND** `Check` is false
- **AND** `req.URL.Path` equals the path of configured `CaptchaCustomJsURL`
- **THEN** the request is passed to origin
- **AND** the captcha HTML MUST NOT be served for that request

#### Scenario: Same path under ban stays blocked
- **WHEN** the remediation kind is ban
- **AND** `req.URL.Path` equals the path of configured `CaptchaCustomJsURL`
- **THEN** the handler applies ban
- **AND** the request MUST NOT pass to origin as captcha passthrough

### Requirement: Passthrough match is exact path only
The match set SHALL be the path of `CaptchaCustomJsURL` plus, when set, the path of optional `captchaCustomChallengeUrl`. Matching SHALL compare `url.Parse` of each configured URL's path to `req.URL.Path`. A configured path MUST be non-empty and start with `/`. Host and query SHALL be ignored. Prefix, directory, and substring matches MUST NOT pass. `CaptchaCustomValidateURL` MUST NOT be in the match set.

#### Scenario: Absolute JS URL matches same-route path
- **WHEN** `CaptchaCustomJsURL` is `https://widget.example/fast.js`
- **AND** the request path is `/fast.js`
- **AND** captcha kind applies
- **THEN** the request matches and passes to origin

#### Scenario: Prefix of the JS path does not match
- **WHEN** `CaptchaCustomJsURL` path is `/assets/fast.js`
- **AND** the request path is `/assets` or `/assets/fast.js/extra`
- **AND** captcha kind applies
- **THEN** the request MUST NOT match passthrough

#### Scenario: Siteverify URL is never a match
- **WHEN** `CaptchaCustomValidateURL` path equals the request path
- **AND** that path is not also `CaptchaCustomJsURL` or `captchaCustomChallengeUrl`
- **AND** captcha kind applies
- **THEN** the request MUST NOT match passthrough

### Requirement: Optional challenge URL is not a required custom field
The plugin SHALL expose optional `captchaCustomChallengeUrl`. Empty SHALL mean the match set is `CaptchaCustomJsURL` path only. Custom-provider validation MUST still require only the existing four custom fields. The default captcha template MUST NOT gain a `ChallengeURL` field from this change.

#### Scenario: Empty challenge URL is valid custom config
- **WHEN** provider is custom
- **AND** the four existing custom fields are set
- **AND** `captchaCustomChallengeUrl` is empty
- **THEN** configuration validation accepts the middleware
- **AND** only the `CaptchaCustomJsURL` path is in the passthrough match set

#### Scenario: Challenge URL adds a second exact path
- **WHEN** `captchaCustomChallengeUrl` parses to path `/v0/challenge`
- **AND** captcha kind applies
- **AND** the request path is `/v0/challenge`
- **THEN** the request matches and passes to origin

### Requirement: Captcha routing does not use cache grace
Captcha-kind routing SHALL decide past-captcha only with `Check` on the request and the client address already chosen for that request. It MUST NOT read or write cache keys for captcha grace, including leftover `{ip}_captcha` entries. It MUST NOT acquire the stream lease or call `Cache().Acquire`.

#### Scenario: Stale cache grace does not pass Check-path
- **WHEN** cache contains `{remoteIP}_captcha`
- **AND** no valid gate cookie is present
- **AND** captcha kind applies
- **THEN** `Check` is false
- **AND** the request is not treated as past-captcha
