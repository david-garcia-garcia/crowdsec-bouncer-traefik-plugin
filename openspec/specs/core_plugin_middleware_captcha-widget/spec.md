## Purpose

Owns how captcha construction pairs challenge-page widget data with a verifier, how `Validate` distinguishes no token from reject, and how ServeHTTP renders, retries, or omits the boot script. Siteverify encoding stays on `core_plugin_middleware_captcha-siteverify`. Assessments stay on `core_plugin_middleware_captcha-assessments`. Gate cookie format stays on `core_plugin_middleware_captcha-gate`.

## Requirements

### Requirement: New is the only provider and key-type switch
Captcha construction SHALL pair one widget with one verifier. `New` SHALL be the only switch on provider name and enterprise key type. `ServeHTTP` and `Validate` MUST NOT mention a provider name or key type. The request path SHALL read only the stored widget and verifier.

#### Scenario: ServeHTTP does not branch on provider name
- **WHEN** a captcha-kind request reaches the challenge handler
- **THEN** the handler chooses render, redirect, or omit-boot from the validate outcome and the stored widget retry flag
- **AND** it does not compare the provider string

### Requirement: Validate outcomes are None, Pass, and Reject
`Validate` SHALL return `(Outcome, error)` with outcomes `None`, `Pass`, and `Reject`. `None` SHALL mean the request is not a POST or the token field is empty. `Pass` SHALL mean the verifier returned true. `Reject` SHALL mean a token was posted and the verifier returned false with no error. Transport failure or an undecodable provider body SHALL be the error return. `(None, err)` is unused. The verifier `Pass` bit SHALL stay `(bool, error)`.

#### Scenario: Empty token is None
- **WHEN** the request is not a POST, or the token field is empty
- **THEN** `Validate` returns `None` and a nil error
- **AND** the verifier is not called

#### Scenario: Verifier true is Pass
- **WHEN** a solver POST has a non-empty token
- **AND** the verifier returns true
- **THEN** `Validate` returns `Pass`

#### Scenario: Verifier false is Reject
- **WHEN** a solver POST has a non-empty token
- **AND** the verifier returns false with no error
- **THEN** `Validate` returns `Reject`

### Requirement: ServeHTTP render, retry, and omit-boot
On `Pass`, the challenge handler SHALL mint `crowdsec_captcha_gate`, set the remediation header to `solved-captcha` when configured, and respond `302 Found` to the request URL. On `None` or error, it SHALL render the challenge with the boot script. On `Reject` when the widget allows retry, it SHALL render the challenge with the boot script. On `Reject` when the widget does not allow retry, it SHALL render the same page with the boot script omitted.

#### Scenario: Pass still mints the gate and redirects
- **WHEN** `Validate` returns `Pass`
- **THEN** the response status is 302
- **AND** the response sets `crowdsec_captcha_gate`

#### Scenario: Checkbox reject re-renders with boot
- **WHEN** `Validate` returns `Reject`
- **AND** the widget allows retry
- **THEN** the solver receives the captcha challenge at 200
- **AND** the boot script is present

#### Scenario: Score reject omits the boot script
- **WHEN** `Validate` returns `Reject`
- **AND** the widget does not allow retry
- **THEN** the solver receives the captcha challenge at 200
- **AND** the boot script is omitted

#### Scenario: None or error renders with boot
- **WHEN** `Validate` returns `None` or an error
- **THEN** the solver receives the captcha challenge at 200
- **AND** the boot script is present
- **AND** no `crowdsec_captcha_gate` cookie is set

### Requirement: Enterprise checkbox and score widgets
When the provider is `recaptcha-enterprise` and the key type is `checkbox`, the widget SHALL load `https://www.google.com/recaptcha/enterprise.js` with no `render=` query, use class `g-recaptcha`, token field `g-recaptcha-response`, and allow retry after reject. When the key type is `score`, the widget SHALL load `https://www.google.com/recaptcha/enterprise.js?render={siteKey}`, use no checkbox class, the same token field `g-recaptcha-response`, and SHALL NOT allow retry after reject. The score boot script SHALL be fixed Go text that calls `grecaptcha.enterprise.ready` then `execute(siteKey, {action})`, writes the token into the hidden field, and submits the form. The boot script MUST NOT be an operator-supplied string. Both key types SHALL keep field name `g-recaptcha-response`.

#### Scenario: Checkbox script has no render query
- **WHEN** the provider is `recaptcha-enterprise` and the key type is `checkbox`
- **THEN** the challenge page script URL is `https://www.google.com/recaptcha/enterprise.js`
- **AND** the page draws a `g-recaptcha` element

#### Scenario: Score script includes render site key
- **WHEN** the provider is `recaptcha-enterprise` and the key type is `score`
- **THEN** the challenge page script URL is `https://www.google.com/recaptcha/enterprise.js?render=` plus the configured site key
- **AND** the page does not draw a `g-recaptcha` checkbox

### Requirement: Stock template placeholders
The stock `captcha.html` SHALL stay one file. Template data SHALL keep `SiteKey`, `FrontendJS`, `FrontendKey`, and `ChallengeURL`, and SHALL gain `BootScript`, `Action`, and `DrawCheckbox`. `DrawCheckbox` SHALL be non-empty when the checkbox div should render. A replaced template that omits the new keys SHALL still work for checkbox when `FrontendJS` is the enterprise script. A replaced template that wants a score key MUST include the boot placeholder.

#### Scenario: Checkbox still works without new placeholders
- **WHEN** the operator uses a template that only has `SiteKey`, `FrontendJS`, `FrontendKey`, and the `g-recaptcha` div
- **AND** the key type is `checkbox`
- **THEN** the challenge page loads `enterprise.js` and draws the checkbox

#### Scenario: Score needs the boot placeholder
- **WHEN** the stock template runs with key type `score`
- **THEN** the page includes the score boot script from `BootScript`

### Requirement: New pairs eucaptcha widget with the eucaptcha verifier
When the provider is `eucaptcha`, captcha construction SHALL pair a Widget with script URL `https://cdn.eu-captcha.eu/verify.js`, class `eu-captcha`, token field `eu-captcha-response`, and retry after reject, together with the eucaptcha verifier. `New` SHALL be the only switch that names `eucaptcha`. The request path MUST NOT compare the provider string. Construction MUST NOT store `eucaptcha` in the siteverify `infoProviders` map. Stock `captcha.html` SHALL stay one file and MUST NOT gain a hardcoded `eu-captcha-response` input. Eucaptcha verify HTTP stays on `core_plugin_middleware_captcha-eucaptcha-verify`.

#### Scenario: Eucaptcha challenge loads verify.js and eu-captcha
- **WHEN** the provider is `eucaptcha`
- **THEN** the challenge page script URL is `https://cdn.eu-captcha.eu/verify.js`
- **AND** the page draws an `eu-captcha` element
- **AND** `Validate` reads the posted token from field `eu-captcha-response`

#### Scenario: ServeHTTP still does not branch on eucaptcha
- **WHEN** a captcha-kind request reaches the challenge handler
- **AND** the stored widget and verifier were paired for `eucaptcha`
- **THEN** the handler chooses render or redirect from the validate outcome and the stored widget retry flag
- **AND** it does not compare the provider string

### Requirement: Validate forwards the request User-Agent into Pass
`Validate` SHALL call `Pass(token, remoteIP, userAgent)` where `userAgent` is `r.UserAgent()` on the challenge request. The verifier `Pass` bit SHALL stay `(bool, error)`. Siteverify and assessments MUST ignore `userAgent`. `Validate` MUST NOT put User-Agent on `clientRequest`. Empty token SHALL stay `None` and MUST NOT call `Pass`.

#### Scenario: Non-empty token passes User-Agent into Pass
- **WHEN** a solver POST has a non-empty token
- **THEN** `Validate` calls `Pass` with that token, the `remoteIP` already passed into `Validate`, and `r.UserAgent()`

#### Scenario: Empty token still does not call Pass
- **WHEN** the request is not a POST, or the token field is empty
- **THEN** `Validate` returns `None` and a nil error
- **AND** the verifier is not called
