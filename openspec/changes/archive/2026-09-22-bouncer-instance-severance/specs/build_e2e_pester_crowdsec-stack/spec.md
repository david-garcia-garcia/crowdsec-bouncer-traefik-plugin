## ADDED Requirements

### Requirement: Instance severance real e2e suite
The repository SHALL provide `tests/e2e/real/instance_severance.Tests.ps1` exercising named LAPI/AppSec slots, late bind, file-provider reload reclaim cases, slot collision, and lifecycle log order from the change requirement matrix (T*, L*, R*, N*, F*, C*, E2/E3). The harness SHALL support rewriting watched dynamic configuration (writable mount or directory) and waiting for Traefik to apply routes without sleep-only synchronization. Lifecycle cases MAY set plugin log level to DEBUG or TRACE and SHALL assert ordered `msg`, `instanceName`, and `incarnation` (and `traefikName` on bouncer lines) in `docker logs traefik-test`. Cases that depend on grace Close SHALL wait at least process reclaim grace plus margin.

#### Scenario: Named share T2 bans both routes
- **WHEN** an owner publishes `shared` LAPI and AppSec on `/api` and a subscriber bounces `/admin` with the same instance names
- **THEN** a banned test IP receives 403 on both paths with distinct remediation headers per route

#### Scenario: L1 subscriber-only first publish 503 then 403
- **WHEN** the dynamic file first contains only subscribers with `streamStartupBlock` true, then adds the owner in a second publish
- **THEN** requests return 503 before the owner exists and 403 from the decision after the owner publish

#### Scenario: F1 slot collision ERROR
- **WHEN** two middlewares attempt to publish the same LAPI instance name with distinct API keys
- **THEN** the second `New` fails and logs `crowdsec instance name taken` at ERROR without the API key
