## MODIFIED Requirements

### Requirement: Real stack boots Traefik and Crowdsec
`tests/e2e/real/config/docker-compose.test.yml` SHALL start Traefik (local plugin bind-mount of the repository root) and Crowdsec. Pester tests SHALL add and delete decisions with `cscli` in the Crowdsec container and send client identity only via `X-Forwarded-For`. Plugin keys in compose labels and file-provider YAML SHALL use the new public names (`lapiEnabled`, `lapiHost`, `lapiMode`, `appsecEnabled`, `bouncerEnabled`, `lapiDefaultDecisionSeconds`, `bouncerClientTrustedIps`, `bouncerBanFilePath`, `captchaEnabled`, `captchaInstanceName`). A captcha-serving route SHALL set `captchaEnabled: true` (empty name fills to the Traefik name). The suite MUST NOT rely on a set `captchaProvider` alone to own captcha.

#### Scenario: Ban then unban on whoami
- **WHEN** the stack is up and a ban decision is added for the test IP
- **THEN** a request to `/whoami` with that `X-Forwarded-For` is forbidden, and after the decision is deleted the same request is allowed

#### Scenario: None mode queries LAPI immediately
- **WHEN** none-mode routes are used and a ban is added
- **THEN** the next request with that `X-Forwarded-For` is forbidden without waiting for a stream interval

#### Scenario: Stream mode uses the stream cache
- **WHEN** stream-mode routes are used and a ban is added
- **THEN** the banned IP is forbidden after the configured stream update interval

#### Scenario: Captcha decision serves the captcha page
- **WHEN** a captcha decision exists for the client
- **AND** the captcha route sets `captchaEnabled: true`
- **THEN** the captcha route returns the captcha HTML rather than a plain allow

#### Scenario: Live mode re-queries after the cached allow expires
- **WHEN** live-mode routes are used, a request is allowed, then a ban is added for that `X-Forwarded-For`
- **THEN** the next request is forbidden only after `lapiDefaultDecisionSeconds`, and a different IP still passes

#### Scenario: Trusted client IP bypasses a ban
- **WHEN** `bouncerClientTrustedIps` includes the test IP and both that IP and an untrusted IP are banned
- **THEN** the trusted `X-Forwarded-For` is allowed and the untrusted one is forbidden

#### Scenario: Custom ban page body and Content-Type
- **WHEN** a ban exists and the route sets `bouncerBanFilePath` to the suite’s custom HTML
- **THEN** the response is forbidden, `Content-Type` is HTML, and the body contains `E2E_CUSTOM_BAN_PAGE_MARKER`

#### Scenario: Real AppSec CRS blocks SQLi
- **WHEN** AppSec is enabled against the Crowdsec CRS inband engine
- **THEN** a benign `/appsec` request is allowed and a SQL-injection query string is forbidden

### Requirement: Real stack covers captcha POST body, grace, and IPv6 bind
Captcha solve SHALL succeed from the POST body alone (no query-string token). A dedicated short-grace route SHALL challenge again after `captchaGracePeriodSeconds`. Gate bind SHALL accept a different spelling of the same IPv6 address.

#### Scenario: POST-body-only captcha solve
- **WHEN** a captcha decision exists and the client POSTs `dummy-captcha-response` only in the form body
- **THEN** the response is 302 with `crowdsec_captcha_gate` and the next GET reaches the backend

#### Scenario: Captcha grace expires
- **WHEN** the short-grace captcha route is solved
- **THEN** a GET with the gate cookie after `captchaGracePeriodSeconds` serves the challenge again
