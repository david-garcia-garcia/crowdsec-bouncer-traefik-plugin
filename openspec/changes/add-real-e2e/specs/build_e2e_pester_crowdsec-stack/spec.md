## Purpose

Defines the Pester real-stack suite that boots Docker Traefik and Crowdsec, loads this plugin as a local Traefik plugin, and asserts remediations against a live LAPI. This is separate from the Traefik-binary + mock-LAPI suite.

## ADDED Requirements

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

### Requirement: CI runs Pester and mock as separate jobs
GitHub Actions on pull requests SHALL run `tests/e2e/real/Test-Integration.ps1` (PowerShell + Pester) in one job and `make e2e_mock` in another. Traefik and Crowdsec image tags SHALL match this tree’s examples (`traefik:v3.7.11`, `crowdsecurity/crowdsec:v1.7.8`).

#### Scenario: Pull request runs both jobs
- **WHEN** a pull request is opened against this repository
- **THEN** one job runs mock e2e and another job runs the Pester real-stack script

### Requirement: Client address comes from Traefik forwarded headers
Scenario requests SHALL identify the client only via `X-Forwarded-For`. The stack SHALL configure Traefik forwarded headers and the plugin `forwardedHeadersTrustedIPs` so the bouncer uses that header. The harness MUST NOT parse `RemoteAddr` as the bouncer client address.

#### Scenario: Banned spoofed IP is remediating
- **WHEN** a test sends `X-Forwarded-For` for a banned IP
- **THEN** the plugin remediates that request as that IP
