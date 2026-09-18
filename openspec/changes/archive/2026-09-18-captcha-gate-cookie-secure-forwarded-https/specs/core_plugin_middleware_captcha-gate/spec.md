## MODIFIED Requirements

### Requirement: Successful solve sets signed gate cookie then redirects
On successful provider verify, the captcha handler SHALL set cookie `crowdsec_captcha_gate` with HttpOnly, Path=/, SameSite=Lax, MaxAge equal to captcha grace seconds, no Domain attribute, and Secure when the request is TLS **or** the request's `X-Forwarded-Proto` (as Traefik's entrypoint left it) equals `https` after trim, compared case-insensitively on the whole value with no comma split. The handler MUST NOT treat `wss`, `Forwarded`, `Front-End-Https`, `X-Forwarded-Protocol`, `X-Scheme`, or `r.URL.Scheme` as grounds for Secure. The cookie value SHALL be `v1.<unix_issued>.<0|1>.<ip>.` plus base64url HMAC-SHA256 of the prefix (bind flag 1 with bound IP string, 0 with empty ip in cookie-only mode). Expiry SHALL be `issued + CaptchaGracePeriodSeconds` with up to 30 seconds clock skew on the low side. HMAC comparison SHALL use constant-time equality.

#### Scenario: Valid cookie passes Check within grace
- **WHEN** the browser presents a gate cookie whose HMAC and expiry are valid
- **AND** bind-IP mode matches the request IP when enabled
- **THEN** `Check` returns true

#### Scenario: Missing or tampered cookie fails Check
- **WHEN** the gate cookie is absent, malformed, expired, or HMAC-invalid
- **THEN** `Check` returns false

#### Scenario: Forwarded https without connection TLS sets Secure
- **WHEN** provider verify succeeds
- **AND** the request has no TLS
- **AND** `X-Forwarded-Proto` is `https` (any case, optional surrounding space)
- **THEN** the set `crowdsec_captcha_gate` cookie has Secure

#### Scenario: Connection TLS sets Secure
- **WHEN** provider verify succeeds
- **AND** the request is TLS
- **THEN** the set `crowdsec_captcha_gate` cookie has Secure

#### Scenario: HTTP proto or absent proto without TLS omits Secure
- **WHEN** provider verify succeeds
- **AND** the request has no TLS
- **AND** `X-Forwarded-Proto` is `http`, `wss`, absent, or empty
- **THEN** the set `crowdsec_captcha_gate` cookie does not have Secure
