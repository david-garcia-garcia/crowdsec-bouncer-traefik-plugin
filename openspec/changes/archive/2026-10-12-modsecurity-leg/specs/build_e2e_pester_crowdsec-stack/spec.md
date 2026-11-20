## ADDED Requirements

### Requirement: Real stack covers ModSecurity CRS inspect
The Pester suite SHALL include domain `modsec` with `modsec.Tests.ps1`, `waf_dual.Tests.ps1`, and `waf_backoff.Tests.ps1`. Compose SHALL start an inspect-only Apache CRS sidecar `waf` (OWASP CRS image, drain/inspect-only, not a reverse-proxy to a second origin) and a second one, `waf-flaky`, that only the ModSec backoff route uses. A Traefik route SHALL send traffic through this plugin with `modsecEnabled` / `modsecUrl` (or bounce `modsecInstanceName`). Client identity SHALL remain `X-Forwarded-For`. The partition in `PesterDomains.ps1` SHALL list every `*.Tests.ps1`, including the ModSec files. Nginx-drain MAY be added when the same whoami/Traefik harness can switch. Bombardier benches MUST NOT be product tests.

#### Scenario: Clean GET is allowed
- **WHEN** the ModSec route receives a benign GET
- **THEN** the backend whoami response is allowed
- **AND** the response has no remediation header

#### Scenario: CRS traversal is blocked
- **WHEN** the ModSec route receives `?test=../etc`
- **THEN** the response is the sidecar 403 with `ban:modsec`
- **AND** whoami is not called
- **AND** the sidecar log names CRS rule 930110 for that URI

#### Scenario: CRS judges a body on GET
- **WHEN** a GET to the ModSec route carries a body
- **THEN** the plugin forwards that body to the sidecar
- **AND** the response is HTTP 403 with `ban:modsec`
- **AND** the sidecar log names CRS rule 920170 for that URI

#### Scenario: A clean OPTIONS body passes
- **WHEN** an OPTIONS request carries a clean JSON body
- **THEN** the request is allowed

#### Scenario: A body payload reaches CRS and the body reaches origin
- **WHEN** a POST body carries an XSS payload
- **THEN** the response is HTTP 403 with `ban:modsec` and the sidecar logs a 941xxx rule
- **AND** a clean POST body is echoed by the origin unchanged

#### Scenario: Body over limit is 413
- **WHEN** the ModSec route sets a small `modsecBodyLimit`
- **AND** the client POST exceeds that limit
- **THEN** the response is HTTP 413
- **AND** the sidecar logs no rule for that URI

#### Scenario: Failure actions on a down sidecar
- **WHEN** the sidecar URL is unreachable
- **THEN** `bouncerModsecFailureAction` `passthrough` lets the request reach whoami with no remediation header
- **AND** `ban` serves the custom ban page with HTTP 403, reason `MODSEC`, and `ban:modsec-failure`
- **AND** `captcha` serves the captcha page with `captcha:modsec-failure`

#### Scenario: WebSocket through the ModSec leg
- **WHEN** a client opens a WebSocket on a ModSec route backed by an echo server
- **THEN** the handshake is inspected and two text frames are echoed on one connection
- **AND** a handshake carrying a CRS payload is blocked with HTTP 403
- **AND** a lone `Upgrade: websocket` header without a Connection upgrade token is still inspected

#### Scenario: Action-rule skip bypasses CRS
- **WHEN** a matching `bypassModsec` (or `bypass`) rule matches
- **AND** the query string would otherwise trip CRS
- **THEN** the request is allowed
- **AND** the same payload on a path the rule does not match is blocked with `ban:modsec`

### Requirement: Real stack covers AppSec and ModSec on one router
Compose SHALL run an AppSec listener on 7424 (`acquis.d/appsec-dual.yaml`) with appsec config `e2e/dual-vpatch`: no CRS, and `DropRequest` when the path contains `appsec-drop`. A file-provider router SHALL use that listener and the CRS sidecar `waf` on one middleware, with an echo origin. The cases SHALL tell the legs apart by `ban:appsec` and `ban:modsec`, and SHALL prove that the sidecar was not called by a unique marker missing from the sidecar log, after a positive control.

#### Scenario: Both legs run in order
- **WHEN** a clean request hits the dual router
- **THEN** the origin answers
- **AND** a CRS payload on a path AppSec allows is blocked with `ban:modsec`

#### Scenario: An AppSec block never reaches the sidecar
- **WHEN** a path contains `appsec-drop` and a CRS payload
- **THEN** the response is HTTP 403 with `ban:appsec`
- **AND** the sidecar log has no line for that request

#### Scenario: Bypass is per leg
- **WHEN** `bypassAppsec` matches
- **THEN** the AppSec drop path is allowed and a CRS payload is still blocked with `ban:modsec`
- **AND** when `bypassModsec` matches, a CRS payload is allowed and the AppSec drop path is still blocked with `ban:appsec`

#### Scenario: Both legs share one body
- **WHEN** a POST body carries an XSS payload that only CRS detects
- **THEN** the response is `ban:modsec` and the sidecar logs an XSS rule for that request
- **AND** a clean POST body is echoed by the origin after both legs read it

### Requirement: Real stack covers the admission gate of both WAF legs
`waf_backoff.Tests.ps1` SHALL cover the AppSec gate with its shipped defaults against `waf-5xx`, and one real outage and recovery per leg. Each outage SHALL stop and start a container only its own route uses: `appsec-flaky-test` (nginx proxy to `crowdsec:7422`) for AppSec, `waf-flaky-test` for ModSec. `AfterAll` SHALL start that container again. Cycle routes SHALL use a 10 s cooldown and the `ban` failure action, and SHALL run the other WAF leg on the same router.

#### Scenario: Default AppSec gate
- **WHEN** a route sets no `appsecUnhealthyBackOffPeriodSecs` and no `bouncerAppsecFailureAction`, and AppSec answers 503
- **THEN** at most 5 requests reach the listener, each banned
- **AND** later requests reach the origin without a ban
- **AND** a fresh stack logs exactly one `crowdsec appsec backoff started` line for that middleware

#### Scenario: AppSec outage and recovery
- **WHEN** `appsec-flaky-test` is stopped
- **THEN** 5 requests answer HTTP 403 with `ban:appsec-failure`
- **AND** the next clean request reaches the origin with no remediation header, while a CRS payload is still blocked with `ban:modsec`
- **AND** after the container starts and the cooldown ends, AppSec answers `ban:appsec` again
- **AND** Traefik logs exactly one `crowdsec appsec backoff started` and one `crowdsec appsec backoff ended` line for that outage

#### Scenario: ModSec outage and recovery
- **WHEN** `waf-flaky-test` is stopped
- **THEN** 5 requests answer HTTP 403 with `ban:modsec-failure`
- **AND** the next clean request and a CRS payload both reach the origin, while the AppSec drop path is still blocked with `ban:appsec`
- **AND** after the container starts and the cooldown ends, the sidecar answers `ban:modsec` again
- **AND** Traefik logs exactly one `crowdsec modsec backoff started` and one `crowdsec modsec backoff ended` line for that outage

## MODIFIED Requirements

### Requirement: CI runs Pester and mock as separate jobs
GitHub Actions on pull requests SHALL run `make e2e_mock` in one job and `tests/e2e/real/Test-Integration.ps1` as a matrix of Pester domains `lapi`, `appsec`, `lifecycle`, and `modsec`. Traefik and Crowdsec image tags SHALL match this tree's examples (`traefik:v3.7.11`, `crowdsecurity/crowdsec:v1.8.0`). Each Pester job SHALL boot its own stack. `Assert-PesterDomainPartition` SHALL fail the job when a `*.Tests.ps1` is missing from the partition.

#### Scenario: Pull request runs mock and four Pester domains
- **WHEN** a pull request is opened against this repository
- **THEN** one job runs mock e2e
- **AND** four jobs run the Pester real-stack script (`lapi`, `appsec`, `lifecycle`, `modsec`)
