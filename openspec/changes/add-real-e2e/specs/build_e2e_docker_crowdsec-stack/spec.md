## Purpose

Defines the Docker Traefik + real Crowdsec end-to-end suite that loads this plugin as a local Traefik plugin and asserts remediations against a live LAPI.

## ADDED Requirements

### Requirement: Isolated Docker scenario per mode
The repository SHALL provide one Docker Compose stack per scenario under `tests/e2e/scenarios/<name>/` that boots Traefik and Crowdsec, loads the plugin from the local tree via Traefik local plugins, and tears the stack down on exit. Scenarios SHALL include at least `stream-mode`, `live-mode`, `none-mode`, `trusted-ips`, `custom-ban-page`, `captcha`, and `appsec`.

#### Scenario: Stream mode ban then unban
- **WHEN** the stream-mode stack is up and a Crowdsec ban decision is added for an IP sent in `X-Forwarded-For`
- **THEN** that IP receives HTTP 403 after a stream tick and receives HTTP 200 after the decision is deleted

#### Scenario: Live mode consults LAPI per request
- **WHEN** the live-mode stack is up and a ban decision is added for an IP
- **THEN** the next request with that `X-Forwarded-For` receives HTTP 403 without waiting for a stream interval

#### Scenario: None mode ignores decisions
- **WHEN** the none-mode stack is up and a ban decision exists for an IP
- **THEN** a request with that `X-Forwarded-For` still receives HTTP 200

#### Scenario: Trusted IPs bypass remediation
- **WHEN** the trusted-ips stack is up and the client address is in the plugin trusted-IP list
- **THEN** the request is allowed even if Crowdsec has a ban for that address

#### Scenario: Custom ban page body
- **WHEN** the custom-ban-page stack is up and the client is banned
- **THEN** the response is HTTP 403 and the body is the configured ban HTML

#### Scenario: Captcha remediation
- **WHEN** the captcha stack is up and Crowdsec has a captcha decision for the client
- **THEN** the response is the captcha challenge page rather than a plain allow

#### Scenario: AppSec blocks a known probe URI
- **WHEN** the appsec stack is up with Crowdsec AppSec collections loaded
- **THEN** a request to the documented probe URI is blocked and a benign URI is allowed

### Requirement: Makefile and CI entry points
The repository SHALL expose `make e2e` (all Docker scenarios, sequential) and `make e2e_<name>` (one scenario). GitHub Actions on pull requests SHALL run `make e2e` in addition to the existing mock suite. The mock suite SHALL remain.

#### Scenario: make e2e runs every Docker scenario
- **WHEN** an operator runs `make e2e`
- **THEN** each scenario directory under `tests/e2e/scenarios/` is executed and a failing scenario fails the make target

#### Scenario: CI runs Docker e2e on pull requests
- **WHEN** a pull request is opened against this repository
- **THEN** a GitHub Actions job runs `make e2e` and a separate job still runs `make e2e_mock`

### Requirement: Client address comes from Traefik forwarded headers
Scenario requests SHALL identify the client only via `X-Forwarded-For`. The stack SHALL configure Traefik forwarded headers and the plugin `forwardedHeadersTrustedIPs` so the bouncer uses that header. The harness MUST NOT parse `RemoteAddr` as the bouncer client address.

#### Scenario: Banned spoofed IP is remediating
- **WHEN** a test sends `X-Forwarded-For: 1.2.3.4` and Crowdsec has a ban for `1.2.3.4`
- **THEN** the plugin remediates that request as that IP (HTTP 403 in stream/live ban cases)

### Requirement: Image pins match this tree’s examples
Docker e2e Traefik and Crowdsec images SHALL match the tags used in this repository’s example compose files (`traefik:v3.7.11`, `crowdsecurity/crowdsec:v1.7.8`) unless those examples change.

#### Scenario: Compose uses example tags
- **WHEN** a Docker e2e compose file is read
- **THEN** Traefik is `traefik:v3.7.11` and Crowdsec is `crowdsecurity/crowdsec:v1.7.8`
