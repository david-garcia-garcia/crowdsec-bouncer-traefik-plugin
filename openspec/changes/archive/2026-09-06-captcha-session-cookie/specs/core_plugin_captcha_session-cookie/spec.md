## Purpose

Plugin-native captcha grace binds a solved challenge to the client address GetRemoteIP already chose plus a session cookie, so shared-IP peers and cookie-less automation do not inherit the bypass.

## ADDED Requirements

### Requirement: Client address for captcha grace is GetRemoteIP
Captcha grace SHALL use the client address `pkg/ip.GetRemoteIP` already produced for the request. Captcha MUST NOT parse `RemoteAddr`, forwarded headers, or the session cookie to invent a second client address.

#### Scenario: Forwarded IP is the grace IP
- **WHEN** Traefik forwards a trusted `X-Forwarded-For` and the bouncer remediates with plugin-native captcha
- **THEN** grace store and check use that GetRemoteIP address, not `RemoteAddr`

### Requirement: Solve issues a session cookie and a token-keyed cache entry
When provider validation succeeds, the plugin SHALL set an HttpOnly cookie named `crowdsec_captcha` whose value is an unguessable token, store captcha-done under a cache key that includes that client IP and that token, with TTL `CaptchaGracePeriodSeconds`, and then redirect as today. The cookie SHALL use Path `/`, SameSite `Lax`, MaxAge equal to the grace period, and Secure when the request has TLS. The plugin MUST NOT add a public Traefik key for cookie name or TTL.

#### Scenario: Solve sets cookie and does not key grace on IP alone
- **WHEN** a client completes captcha validation
- **THEN** the response includes `Set-Cookie` for `crowdsec_captcha` and a later request from the same IP without that cookie is not treated as solved

### Requirement: Check requires the matching cookie for that IP
A later request SHALL pass captcha grace only when it presents `crowdsec_captcha` whose token matches a live cache entry for that same GetRemoteIP address. Missing cookie, unknown token, expired entry, or a token issued for a different IP SHALL be treated as unsolved. A leftover cache key that is only `{ip}_captcha` MUST NOT count as solved.

#### Scenario: Shared IP without the solver cookie is unsolved
- **WHEN** one client behind an IP has solved captcha and another client on the same IP sends a request without `crowdsec_captcha`
- **THEN** the second client is served the captcha page, not the backend

#### Scenario: Matching cookie on the same IP is solved
- **WHEN** the solver returns with the issued `crowdsec_captcha` cookie while the grace entry is live
- **THEN** the request proceeds past captcha (same as today’s solved path)

#### Scenario: Cookie copied to another IP is unsolved
- **WHEN** a request presents a valid solver cookie but GetRemoteIP is a different address
- **THEN** captcha is not considered solved

### Requirement: AppSec challenge cookies stay a separate path
Plugin-native captcha grace MUST NOT parse or set `__crowdsec_challenge` or AppSec `user_cookies`. AppSec challenge relay SHALL keep its existing Set-Cookie behavior.

#### Scenario: AppSec challenge cookie is not captcha grace
- **WHEN** a request carries `__crowdsec_challenge` and has a captcha LAPI decision but no `crowdsec_captcha` cookie
- **THEN** plugin-native captcha Check does not treat the request as solved
