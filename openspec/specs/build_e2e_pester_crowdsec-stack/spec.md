## Purpose

Defines the Pester real-stack suite that boots Docker Traefik and Crowdsec, loads this plugin as a local Traefik plugin, and asserts remediations against a live LAPI. This is separate from the Traefik-binary + mock-LAPI suite.

## Requirements

### Requirement: Pester suite is separate from mock e2e
The repository SHALL keep `tests/e2e/mock/` and `make e2e_mock` as the mock suite. Real-stack coverage SHALL live entirely under `tests/e2e/real/` (`Test-Integration.ps1`, `docker-compose.test.yml`, `*.Tests.ps1`) and SHALL NOT replace the mock suite or share that folder.

#### Scenario: Mock suite still present
- **WHEN** a reviewer inspects `tests/e2e/mock/` and `.github/workflows/e2e.yml`
- **THEN** `make e2e_mock` still exists and CI still has a job that runs it

#### Scenario: Real suite is its own folder
- **WHEN** a reviewer inspects `tests/e2e/`
- **THEN** Pester cases, the compose file, and `Test-Integration.ps1` are under `tests/e2e/real/` and not at the repository root or mixed into `tests/e2e/mock/`

### Requirement: Real stack boots Traefik and Crowdsec
`tests/e2e/real/docker-compose.test.yml` SHALL start Traefik (local plugin bind-mount of the repository root) and Crowdsec. Pester tests SHALL add and delete decisions with `cscli` in the Crowdsec container and send client identity only via `X-Forwarded-For`.

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
- **THEN** the captcha route returns the captcha HTML rather than a plain allow

#### Scenario: Live mode re-queries after the cached allow expires
- **WHEN** live-mode routes are used, a request is allowed, then a ban is added for that `X-Forwarded-For`
- **THEN** the next request is forbidden only after `defaultDecisionSeconds`, and a different IP still passes

#### Scenario: Trusted client IP bypasses a ban
- **WHEN** `clientTrustedIPs` includes the test IP and both that IP and an untrusted IP are banned
- **THEN** the trusted `X-Forwarded-For` is allowed and the untrusted one is forbidden

#### Scenario: Custom ban page body and Content-Type
- **WHEN** a ban exists and the route sets `banHtmlFilePath` to the suite’s custom HTML
- **THEN** the response is forbidden, `Content-Type` is HTML, and the body contains `E2E_CUSTOM_BAN_PAGE_MARKER`

#### Scenario: Real AppSec CRS blocks SQLi
- **WHEN** AppSec is enabled against the Crowdsec CRS inband engine
- **THEN** a benign `/appsec` request is allowed and a SQL-injection query string is forbidden

### Requirement: CI runs Pester and mock as separate jobs
GitHub Actions on pull requests SHALL run `tests/e2e/real/Test-Integration.ps1` (PowerShell + Pester) in one job and `make e2e_mock` in another. Traefik and Crowdsec image tags SHALL match this tree’s examples (`traefik:v3.7.11`, `crowdsecurity/crowdsec:v1.8.0`).

#### Scenario: Pull request runs both jobs
- **WHEN** a pull request is opened against this repository
- **THEN** one job runs mock e2e and another job runs the Pester real-stack script

### Requirement: Client address comes from Traefik forwarded headers
Scenario requests SHALL identify the client only via `X-Forwarded-For`. The stack SHALL configure Traefik forwarded headers and the plugin `forwardedHeadersTrustedIPs` so the bouncer uses that header. The harness MUST NOT parse `RemoteAddr` as the bouncer client address.

#### Scenario: Banned spoofed IP is remediating
- **WHEN** a test sends `X-Forwarded-For` for a banned IP
- **THEN** the plugin remediates that request as that IP

### Requirement: Real stack includes a Dragonfly Redis-protocol cache
`tests/e2e/real/docker-compose.test.yml` SHALL start Dragonfly (`docker.dragonflydb.io/dragonflydb/dragonfly:v1.40.2`, port 6379, `ulimits.memlock: -1`) in addition to Traefik and Crowdsec. At least one Pester route SHALL set `redisCacheEnabled` and `redisCacheHost` to that Dragonfly service. Pester SHALL prove live-mode cache hit/miss against Dragonfly. Client identity SHALL remain only `X-Forwarded-For` (Traefik forwarded headers plus plugin `forwardedHeadersTrustedIps`).

#### Scenario: Live-mode Redis cache allow then ban after TTL
- **WHEN** the Dragonfly-backed live-mode route is used, a request is allowed, then a ban is added for that `X-Forwarded-For`
- **THEN** the next request is still allowed until `defaultDecisionSeconds`, after which the same IP is forbidden and a different IP still passes

#### Scenario: Cached ban survives Traefik restart
- **WHEN** a ban is cached in Dragonfly for the test IP and the Traefik container is restarted
- **THEN** a request with that `X-Forwarded-For` is still forbidden without waiting for a new LAPI miss (in-memory-only cache would miss)

### Requirement: Real stack covers Range and header-mapped scopes
The Pester suite SHALL include cases that inject CrowdSec `Range` decisions with `cscli decisions add --range` and at least one header-mapped scope (`--scope` / `--value`) against the live LAPI. A dedicated compose middleware SHALL set `decisionScopeHeaders`. Range SHALL be proven in stream mode (cache) and none mode (LAPI `?ip=`). Country matching SHALL use a geoenrich Traefik plugin (traefik-geoblock in enrich mode) that writes the mapped country header from a **public** client IP. The suite MUST NOT inject a client-set country header for that Country case. Client IP identity SHALL remain `X-Forwarded-For`. Nested plugin maps (`decisionScopeHeaders`, geoblock `databaseSources`) SHALL be loaded from a file provider.

#### Scenario: Range ban contains the test IP
- **WHEN** a Range ban covers the test client subnet and the request uses that `X-Forwarded-For`
- **THEN** the real-stack route is forbidden, and an IP outside the Range is allowed

#### Scenario: Header-mapped Country ban via geoenrich
- **WHEN** geoblock enrich writes `X-IPCountry` for a public `X-Forwarded-For`, `decisionScopeHeaders` maps `Country` to that header, and a Country ban exists for the enriched code
- **THEN** the real-stack route is forbidden for that public IP, and a private IP (country skipped) is allowed

### Requirement: Real stack covers AppSec bot-detection challenge
The Pester suite SHALL boot Crowdsec `v1.8.0` with AppSec bot-detection loaded (`crowdsecurity/appsec-bot-*` or the published 1.8 hub equivalent) in addition to CRS inband. A Traefik route SHALL send `/crowdsec-internal/challenge` through the same AppSec-enabled bouncer middleware, with the service backend on Crowdsec AppSec port 7423 (CRS stays on 7422). Client identity SHALL remain `X-Forwarded-For`. Existing CRS allow/block cases on `/appsec` SHALL remain.

#### Scenario: Challenge is not a silent 403
- **WHEN** bot-detection is loaded and a client without a solved challenge cookie requests the bot-detection route
- **THEN** the response is not a bare operator ban 403 with an empty AppSec body; it carries the AppSec challenge payload (HTML and/or `__crowdsec_challenge` Set-Cookie) or an explicit allow if the engine exempts the client

#### Scenario: CRS inband still blocks SQLi
- **WHEN** AppSec CRS inband is still enabled on `/appsec`
- **THEN** a benign `/appsec` request is allowed and a SQL-injection query string is forbidden

