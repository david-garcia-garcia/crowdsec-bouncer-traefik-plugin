## MODIFIED Requirements

### Requirement: CI runs Pester and mock as separate jobs
GitHub Actions on pull requests SHALL run `tests/e2e/real/Test-Integration.ps1` (PowerShell + Pester) in one job and `make e2e_mock` in another. Traefik and Crowdsec image tags SHALL match this tree’s examples (`traefik:v3.7.11`, `crowdsecurity/crowdsec:v1.8.0`).

#### Scenario: Pull request runs both jobs
- **WHEN** a pull request is opened against this repository
- **THEN** one job runs mock e2e and another job runs the Pester real-stack script

## ADDED Requirements

### Requirement: Real stack covers AppSec bot-detection challenge
The Pester suite SHALL boot Crowdsec `v1.8.0` with AppSec bot-detection loaded (`crowdsecurity/appsec-bot-*` or the published 1.8 hub equivalent) in addition to CRS inband. A Traefik route SHALL send `/crowdsec-internal/challenge` through the same AppSec-enabled bouncer middleware, with the service backend on Crowdsec AppSec port 7422. Client identity SHALL remain `X-Forwarded-For`. Existing CRS allow/block cases on `/appsec` SHALL remain.

#### Scenario: Challenge is not a silent 403
- **WHEN** bot-detection is loaded and a client without a solved challenge cookie requests the bot-detection route
- **THEN** the response is not a bare operator ban 403 with an empty AppSec body; it carries the AppSec challenge payload (HTML and/or `__crowdsec_challenge` Set-Cookie) or an explicit allow if the engine exempts the client

#### Scenario: CRS inband still blocks SQLi
- **WHEN** AppSec CRS inband is still enabled on `/appsec`
- **THEN** a benign `/appsec` request is allowed and a SQL-injection query string is forbidden
