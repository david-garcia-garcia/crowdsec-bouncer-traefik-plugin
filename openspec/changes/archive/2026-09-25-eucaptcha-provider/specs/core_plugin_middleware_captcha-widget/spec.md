## ADDED Requirements

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
