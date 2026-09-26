## Purpose

Owns how `handleRemediationServeHTTP` routes captcha-kind requests after the gate cookie and first-solve 302: solved-form POST redirect, exact-path custom challenge-resource passthrough, and HEAD on the captcha path. Cookie grace stays on `core_plugin_middleware_captcha-gate`.

## Requirements

### Requirement: Captcha-kind routing includes HEAD
When captcha is configured and the remediation kind is captcha, the remediation handler SHALL apply captcha routing for every HTTP method, including HEAD. A HEAD request from a client carrying a captcha remediation SHALL receive the captcha challenge page; it MUST NOT receive the ban page. This is a ratified behavior, not an incidental consequence of routing: it SHALL be asserted by a named test. Ban kind SHALL stay on the ban path.

#### Scenario: Captcha HEAD serves the challenge page
- **WHEN** captcha is configured
- **AND** the request method is HEAD
- **AND** the remediation kind is captcha
- **AND** the path is not a configured custom challenge resource
- **AND** `Check` is false
- **THEN** the handler serves the captcha challenge page with the captcha remediation header
- **AND** it MUST NOT fall through to ban

#### Scenario: Ban HEAD stays ban
- **WHEN** the remediation kind is ban
- **AND** the request method is HEAD
- **THEN** the handler applies ban
- **AND** captcha routing MUST NOT run

### Requirement: Solved captcha-form POST does not reach origin
When captcha kind applies and `Check` is true, a captcha-form POST SHALL receive `302 Found` to the same request URL. The handler MUST NOT forward that POST to origin. A GET that only carries the provider field in the query is not a form POST. An ordinary POST that does not carry the provider response field SHALL still reach origin after `Check` is true, with its body unchanged.

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

### Requirement: Captcha-form detection never costs origin its body
Captcha-form detection runs on requests that may still be forwarded, so it SHALL be its own reader, separate from the first-verify provider-token reader used when the plugin answers the request itself. The two callers MUST NOT share one helper. Detection SHALL inspect at most 64KiB of body; a request whose declared or actual body exceeds that SHALL NOT be treated as a captcha form. It SHALL read `application/x-www-form-urlencoded` and `multipart/form-data` bodies, and SHALL read a body with no usable `Content-Type` as urlencoded. When the form was already parsed upstream, detection SHALL answer from the parsed values instead of rereading the body. Whenever the answer is no, the body and `Content-Length` SHALL be left readable so origin receives the request intact.

#### Scenario: Over-maximum POST reaches origin unchanged
- **WHEN** `Check` is true and the request is a POST whose body is larger than 64KiB
- **AND** that body contains the provider response field name
- **THEN** the request is not treated as a captcha form
- **AND** origin receives every byte of the original body

#### Scenario: Multipart captcha form is detected
- **WHEN** captcha kind applies and `Check` is true
- **AND** the request is a `multipart/form-data` POST carrying a non-empty provider response field
- **THEN** the response is `302 Found`
- **AND** origin MUST NOT receive the POST

#### Scenario: Unknown content length behaves sanely
- **WHEN** the request declares no content length
- **THEN** a body within 64KiB is still inspected for the provider field
- **AND** a body over 64KiB is not treated as a captcha form and reaches origin unchanged

#### Scenario: Already-parsed form is answered from parsed values
- **WHEN** an upstream handler already parsed the POST form
- **THEN** detection answers from the parsed values without rereading the body

### Requirement: Solved-form redirect does not remint or re-verify
The Check-true form-POST redirect SHALL set the configured remediation header to `captcha:solved` when that header name is configured. `captcha:solved` SHALL NOT take a third field. It MUST NOT remint the gate cookie. It MUST NOT call the captcha provider. First-solve cookie mint and 302 stay on the captcha challenge handler.

#### Scenario: Check-true form POST keeps the existing cookie
- **WHEN** a captcha-form POST is redirected because `Check` is true
- **THEN** the response is `302 Found`
- **AND** no new gate cookie is issued
- **AND** the provider siteverify endpoint is not called

#### Scenario: Check-true form POST header is captcha:solved
- **WHEN** a captcha-form POST is redirected because `Check` is true
- **AND** the remediation header name is configured
- **THEN** that header value is `captcha:solved`

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
The match set SHALL be the path of `CaptchaCustomJsURL` plus, when set, the path of optional `captchaCustomChallengeUrl`. Matching SHALL compare `url.Parse` of each configured URL's path to `req.URL.Path`. A configured path MUST be non-empty and start with `/`. Host and query SHALL be ignored. Prefix, directory, and substring matches MUST NOT pass. `CaptchaCustomValidateURL` MUST NOT be in the match set. One owner SHALL derive a resource path from a configured value, so configuration validation and request matching cannot disagree about which values name a path.

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
The plugin SHALL expose optional `captchaCustomChallengeUrl`. Empty SHALL mean the match set is `CaptchaCustomJsURL` path only. Custom-provider validation MUST still require only the existing four custom fields. When the key is non-empty on a custom provider, configuration validation SHALL reject a value that names no absolute path, because no browser request could ever match it. A built-in provider SHALL ignore the key. The bundled default `captcha.html` MUST NOT gain a `ChallengeURL` placeholder from this change.

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

#### Scenario: Challenge URL that names no path is rejected
- **WHEN** provider is custom
- **AND** `captchaCustomChallengeUrl` is set to a value with no absolute path
- **THEN** configuration validation returns an error naming the key

### Requirement: Captcha template renders the configured challenge URL
The captcha HTML execute data SHALL include `ChallengeURL` beside `SiteKey`, `FrontendJS`, and `FrontendKey`. It SHALL carry `captchaCustomChallengeUrl` for a custom provider and SHALL be empty otherwise, so a self-hosted widget is pointed at its challenge endpoint from configuration instead of a hard-coded template. The `examples/custom-captcha` template SHALL use that variable, and that example's compose labels and README SHALL set the key. `README.md` SHALL document the key alongside the other captcha keys, with its default.

#### Scenario: Custom provider renders its challenge URL
- **WHEN** provider is custom and `captchaCustomChallengeUrl` is set
- **AND** the captcha challenge page is served from a template using `ChallengeURL`
- **THEN** the rendered page carries the configured challenge URL

#### Scenario: Built-in provider renders an empty challenge URL
- **WHEN** provider is a built-in provider
- **AND** the captcha template references `ChallengeURL`
- **THEN** the rendered value is empty and template execution still succeeds

### Requirement: Captcha routing does not use store grace
Captcha-kind routing SHALL decide past-captcha only with `Check` on the request and the client address already chosen for that request. It MUST NOT read or write store keys for captcha grace, including leftover `{ip}_captcha` entries. It MUST NOT acquire a stream lease.

#### Scenario: Stale grace key does not pass Check-path
- **WHEN** a leftover `{remoteIP}_captcha` key exists
- **AND** no valid gate cookie is present
- **AND** captcha kind applies
- **THEN** `Check` is false
- **AND** the request is not treated as past-captcha
