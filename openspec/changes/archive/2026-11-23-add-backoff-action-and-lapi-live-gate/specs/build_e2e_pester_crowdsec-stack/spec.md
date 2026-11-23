## MODIFIED Requirements

### Requirement: Real stack covers LAPI and AppSec failure actions
The Pester suite SHALL include none-mode routes whose LAPI or AppSec host is unreachable, with `bouncerLapiFailureAction` / `bouncerAppsecFailureAction` set to `ban` and `passthrough`. Those routes SHALL set `lapiHttpTimeoutSeconds` and `appsecHttpTimeoutSeconds` to 60 where the suite previously set `httpTimeoutSeconds: 60`, or to 2 on the unreachable-host routes that previously used a short shared timeout. The suite MUST NOT keep `httpTimeoutSeconds`. The unreachable-LAPI routes SHALL set `lapiUnhealthyBackOffPeriodSecs: 0` and the unreachable-AppSec routes `appsecUnhealthyBackOffPeriodSecs: 0`, so every request exercises the failure action and none is a gate skip.

#### Scenario: Unreachable LAPI passthrough
- **WHEN** LAPI is unreachable and `bouncerLapiFailureAction` is `passthrough`
- **THEN** the request is allowed

#### Scenario: Unreachable LAPI ban
- **WHEN** LAPI is unreachable and `bouncerLapiFailureAction` is `ban`
- **THEN** the request is forbidden

#### Scenario: Unreachable AppSec passthrough
- **WHEN** AppSec is unreachable and `bouncerAppsecFailureAction` is `passthrough`
- **THEN** the request is allowed

#### Scenario: Unreachable AppSec ban
- **WHEN** AppSec is unreachable and `bouncerAppsecFailureAction` is `ban`
- **THEN** the request is forbidden

#### Scenario: Unreachable LAPI passthrough never backs off
- **WHEN** the readiness probe and the cases have sent more than 5 requests to the unreachable-LAPI passthrough route
- **THEN** every request is still allowed with no `ban:lapi-backoff`

### Requirement: Real stack covers the admission gate of both WAF legs
`waf_backoff.Tests.ps1` SHALL cover the AppSec gate with its shipped defaults against `waf-5xx`, one real outage and recovery per leg, and one router with a non-default backoff action. Each outage SHALL stop and start a container only its own routes use: `appsec-flaky-test` (nginx proxy to `crowdsec:7422`) for AppSec, `waf-flaky-test` for ModSec. `AfterAll` SHALL start that container again. Cycle routes SHALL use a 10 s cooldown and the `ban` failure action, and SHALL run the other WAF leg on the same router. The ModSec failure-action routes on an unreachable sidecar SHALL set `modsecUnhealthyBackOffPeriodSecs: 0`.

#### Scenario: Default AppSec gate
- **WHEN** a route sets no `appsecUnhealthyBackOffPeriodSecs`, no `bouncerAppsecFailureAction`, and no `bouncerAppsecBackOffAction`, and AppSec answers 503
- **THEN** every request reaches the origin with no remediation header
- **AND** at most 5 requests reach the listener
- **AND** a fresh stack logs exactly one `crowdsec appsec backoff started` line for that middleware

#### Scenario: AppSec outage and recovery
- **WHEN** `appsec-flaky-test` is stopped
- **THEN** 5 requests answer HTTP 403 with `ban:appsec-failure`
- **AND** the next clean request reaches the origin with no remediation header, while a CRS payload is still blocked with `ban:modsec`
- **AND** after the container starts and the cooldown ends, AppSec answers `ban:appsec` again
- **AND** Traefik logs exactly one `crowdsec appsec backoff started` and one `crowdsec appsec backoff ended` line for that outage

#### Scenario: Shared gate with a per-router backoff action
- **WHEN** a second router subscribes to the AppSec instance of the AppSec cycle route and sets `bouncerAppsecBackOffAction: ban`
- **AND** the AppSec cycle has tripped the shared gate
- **THEN** a clean request on the second router answers HTTP 403 with `ban:appsec-backoff` while the cycle route's clean request reaches the origin
- **AND** `appsec-flaky-test` receives no request from either router while the gate backs off

#### Scenario: ModSec outage and recovery
- **WHEN** `waf-flaky-test` is stopped
- **THEN** 5 requests answer HTTP 403 with `ban:modsec-failure`
- **AND** the next clean request and a CRS payload both reach the origin, while the AppSec drop path is still blocked with `ban:appsec`
- **AND** after the container starts and the cooldown ends, the sidecar answers `ban:modsec` again
- **AND** Traefik logs exactly one `crowdsec modsec backoff started` and one `crowdsec modsec backoff ended` line for that outage

## ADDED Requirements

### Requirement: Real stack covers the LAPI live admission gate
`lapi_backoff.Tests.ps1`, in Pester domain `lapi`, SHALL cover one LAPI outage and recovery on a `live` route. Its LAPI host SHALL be compose service `lapi-flaky` (container `lapi-flaky-test`, nginx proxy to `crowdsec:8080`) that no other route uses. The route SHALL use its own bouncer key, a 10 s cooldown, and a 2 s LAPI timeout. `AfterAll` SHALL start the container again. The suite MUST NOT stop `crowdsec`.

#### Scenario: LAPI outage and recovery
- **WHEN** `lapi-flaky-test` is stopped and each request carries a fresh `X-Forwarded-For`
- **THEN** 5 requests answer HTTP 403 with `ban:lapi-failure`
- **AND** the next request answers HTTP 403 with `ban:lapi-backoff` well under the 2 s LAPI timeout
- **AND** after the container starts and the cooldown ends, a clean request reaches the origin
- **AND** Traefik logs exactly one `crowdsec lapi backoff started` and one `crowdsec lapi backoff ended` line for that outage
