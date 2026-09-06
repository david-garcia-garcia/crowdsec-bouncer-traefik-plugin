## Purpose

Governs pass-through of custom captcha JS and challenge resource requests when the client has a captcha remediation, without weakening ban.

## Requirements

### Requirement: CaptchaCustomChallengeURL is optional public config
Public config `captchaCustomChallengeUrl` SHALL exist on `Config` as `CaptchaCustomChallengeURL`. Default SHALL be empty. When `captchaProvider` is `custom`, empty SHALL be valid (existing required custom fields unchanged). Non-empty SHALL be stored on the captcha Client with `CaptchaCustomJsURL`.

#### Scenario: Custom provider still valid without challenge URL
- **WHEN** `captchaProvider` is `custom` and the four existing custom fields are set and `CaptchaCustomChallengeURL` is omitted
- **THEN** plugin initialization succeeds

### Requirement: Captcha Client owns custom resource path match
The captcha Client SHALL decide whether a request path is a custom resource. It SHALL parse each configured JS and challenge URL, take `url.Path`, and compare it to `req.URL.Path` (exact, no prefix). Scheme, host, query, and fragment MUST NOT participate. Empty configured values MUST NOT match. A value that is not a URL with a path SHALL match only when it is a path starting with `/` compared exactly to `req.URL.Path`. Non-custom providers MUST NOT treat CDN JS URLs as pass-through resources.

#### Scenario: Absolute JS URL matches browser path
- **WHEN** `CaptchaCustomJsURL` is `http://captcha.localhost:8000/fast.js`
- **AND** the request path is `/fast.js`
- **THEN** the captcha Client reports a custom resource match

#### Scenario: Challenge query is ignored
- **WHEN** `CaptchaCustomChallengeURL` is `/v0/challenge`
- **AND** the request path is `/v0/challenge` with a query string
- **THEN** the captcha Client reports a custom resource match

#### Scenario: Other paths do not match
- **WHEN** `CaptchaCustomJsURL` is `/fast.js`
- **AND** the request path is `/foo`
- **THEN** the captcha Client does not report a custom resource match

### Requirement: Captcha remediation passes matching resources to origin
When remediation kind is captcha, the captcha Client is valid, provider is custom, and the request is a custom resource match, the bouncer SHALL call the existing pass path (`handleNextServeHTTP`) and MUST NOT serve captcha HTML. That pass-through SHALL apply for every HTTP method, including HEAD. Client address SHALL remain `clientRequest.remoteIP` from `pkg/ip.GetRemoteIP`; the pass-through MUST NOT parse `RemoteAddr`.

#### Scenario: Captcha-flagged GET for JS reaches next
- **WHEN** the cached or live verdict is captcha
- **AND** the request is `GET /fast.js` matching `CaptchaCustomJsURL`
- **THEN** the next handler runs
- **AND** captcha HTML is not written

#### Scenario: Captcha-flagged HEAD for JS reaches next
- **WHEN** the cached or live verdict is captcha
- **AND** the request is `HEAD /fast.js` matching `CaptchaCustomJsURL`
- **THEN** the next handler runs
- **AND** the request is not banned for the captcha-HEAD fallback

### Requirement: Ban remediation never passes custom resources
When remediation kind is ban, matching JS or challenge paths SHALL still be banned. Pass-through MUST NOT apply.

#### Scenario: Banned GET for JS stays banned
- **WHEN** the cached or live verdict is ban
- **AND** the request is `GET /fast.js` matching `CaptchaCustomJsURL`
- **THEN** the ban template or ban status is written
- **AND** the next handler does not run

### Requirement: Unmatched captcha HEAD still bans
When remediation kind is captcha and the request is HEAD and is not a custom resource match, the bouncer SHALL keep today’s fallback to ban.

#### Scenario: Captcha HEAD for an app path still bans
- **WHEN** the cached or live verdict is captcha
- **AND** the request is `HEAD /foo` and is not a custom resource match
- **THEN** the response is the ban fallback, not captcha HTML

### Requirement: Template map includes ChallengeURL
Captcha HTML execute data SHALL include `ChallengeURL` set from `CaptchaCustomChallengeURL` (empty when unset). Default bundled `captcha.html` MAY omit that placeholder. The custom-captcha example SHALL use it.

#### Scenario: Custom example template uses ChallengeURL
- **WHEN** the custom-captcha example template is rendered with `CaptchaCustomChallengeURL` set
- **THEN** the challenge widget attribute uses that configured URL
