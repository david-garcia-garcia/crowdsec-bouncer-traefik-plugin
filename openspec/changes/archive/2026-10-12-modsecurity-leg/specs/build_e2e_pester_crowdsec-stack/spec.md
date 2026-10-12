## ADDED Requirements

### Requirement: Real stack covers ModSecurity CRS inspect
The Pester suite SHALL include domain `modsec`. Compose SHALL start an inspect-only Apache CRS sidecar (OWASP CRS image, drain/inspect-only, not a reverse-proxy to a second origin). A Traefik route SHALL send traffic through this plugin with `modsecEnabled` / `modsecUrl` (or bounce `modsecInstanceName`). Client identity SHALL remain `X-Forwarded-For`. The partition in `PesterDomains.ps1` SHALL list every `*.Tests.ps1`, including the new ModSec files. Nginx-drain MAY be added when the same whoami/Traefik harness can switch. Bombardier benches MUST NOT be product tests.

#### Scenario: Clean GET is allowed
- **WHEN** the ModSec route receives a benign GET
- **THEN** the backend whoami response is allowed

#### Scenario: CRS traversal is blocked
- **WHEN** the ModSec route receives `?test=../etc`
- **THEN** the request is forbidden
- **AND** whoami is not called

#### Scenario: Body over limit is 413
- **WHEN** the ModSec route sets a small `modsecBodyLimit`
- **AND** the client POST exceeds that limit
- **THEN** the response is HTTP 413

#### Scenario: Deny GET-with-body is 400
- **WHEN** the default deny-verbs list applies
- **AND** a GET carries a body
- **THEN** the response is HTTP 400

#### Scenario: FailMode close on down sidecar
- **WHEN** `bouncerModsecFailMode` is `close` and the sidecar URL is unreachable
- **THEN** the response is HTTP 502

#### Scenario: FailMode open on down sidecar
- **WHEN** `bouncerModsecFailMode` is `open` and the sidecar URL is unreachable
- **THEN** the request is allowed

#### Scenario: Backoff skip is unhealthy
- **WHEN** backoff is enabled with threshold 1 and the sidecar is down
- **THEN** a later request does not call the sidecar and follows failMode

#### Scenario: Action-rule skip bypasses CRS
- **WHEN** a matching `bypassModsec` (or `bypass`) rule matches
- **AND** the query string would otherwise trip CRS
- **THEN** the request is allowed

## MODIFIED Requirements

### Requirement: CI runs Pester and mock as separate jobs
GitHub Actions on pull requests SHALL run `make e2e_mock` in one job and `tests/e2e/real/Test-Integration.ps1` as a matrix of Pester domains `lapi`, `appsec`, `lifecycle`, and `modsec`. Traefik and Crowdsec image tags SHALL match this tree's examples (`traefik:v3.7.11`, `crowdsecurity/crowdsec:v1.8.0`). Each Pester job SHALL boot its own stack. `Assert-PesterDomainPartition` SHALL fail the job when a `*.Tests.ps1` is missing from the partition.

#### Scenario: Pull request runs mock and four Pester domains
- **WHEN** a pull request is opened against this repository
- **THEN** one job runs mock e2e
- **AND** four jobs run the Pester real-stack script (`lapi`, `appsec`, `lifecycle`, `modsec`)
