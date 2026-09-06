## Purpose

Stops an already-solved captcha form POST from reaching origin as POST, so GET-only backends do not return 405 when a second tab submits the same captcha form.

## ADDED Requirements

### Requirement: Solved captcha form POST redirects
When captcha remediation still applies to the client and captcha grace already records that client as solved, a POST that carries the configured captcha provider response field SHALL NOT be forwarded to origin. The plugin SHALL respond with HTTP 302 Found to the request URL, matching the redirect after the first successful captcha verify. When a remediation custom header is configured, that header SHALL be `solved-captcha` on this response. The plugin SHALL NOT call the captcha provider again for that POST.

#### Scenario: Second-tab captcha POST after grace
- **WHEN** captcha grace is set for the client and the client POSTs the same URL with the provider response field populated
- **THEN** the plugin returns 302 Found to that URL and origin is not invoked

#### Scenario: Remediation header on solved redirect
- **WHEN** a remediation custom header is configured and a solved captcha form POST is intercepted
- **THEN** that header is `solved-captcha`

### Requirement: Grace pass-through keeps ordinary requests
GET and other methods during captcha grace SHALL still follow the existing pass path (including AppSec when enabled). A POST that does not carry the configured provider response field SHALL still be forwarded, and origin SHALL receive that POST body.

#### Scenario: GET during grace reaches origin
- **WHEN** captcha grace is set and the client GETs a protected URL
- **THEN** the request is passed through as today

#### Scenario: Origin form POST during grace keeps its body
- **WHEN** captcha grace is set and the client POSTs without the captcha provider response field
- **THEN** origin is invoked with that POST and the original body

### Requirement: Provider response field is the configured name
Detection SHALL use the captcha provider’s response field (`h-captcha-response`, `g-recaptcha-response`, `cf-turnstile-response`, or the operator’s custom response field). Detection MUST NOT key only off the config key name `captchaCustomResponse`.

#### Scenario: Built-in hcaptcha field
- **WHEN** the provider is hcaptcha and the POST includes `h-captcha-response`
- **THEN** the request is treated as a captcha form POST

#### Scenario: Custom provider field
- **WHEN** the provider is custom and the POST includes the configured custom response field
- **THEN** the request is treated as a captcha form POST

### Requirement: Grace key uses the chosen client address
Captcha grace lookup SHALL use the client address already chosen for the request (`GetRemoteIP` / `clientRequest.remoteIP`). The request path MUST NOT re-parse `RemoteAddr` to build the grace key.

#### Scenario: Grace check reuses remoteIP
- **WHEN** the bouncer applies captcha remediation
- **THEN** captcha grace is read with the same remoteIP already attached to that request
