## Purpose

Traefik Yaegi loads `CreateConfig` and `New` from the module-root package. `New` uses the constructor context as the reclaim holder and returns a per-router Bouncer that holds request policy and MUST NOT start a process-wide stream ticker.

## Requirements

### Requirement: Yaegi constructors stay on the module-root package
The plugin SHALL export `CreateConfig` and `New` from the package Traefik loads for `.traefik.yml` `import` (the module root). `New` SHALL take Traefik’s constructor context and MUST NOT ignore it.

#### Scenario: Catalog import still constructs
- **WHEN** Traefik loads `github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin`
- **THEN** `CreateConfig` and `New` exist on that package
- **AND** `New` receives a non-ignored context used as the reclaim holder

### Requirement: Bouncer does not own the stream
The per-router bouncer SHALL handle request policy (trusted IPs, ban/captcha pages, whether AppSec runs on pass, LAPI failure action, Redis fail-closed, and live-cache TTL) and MUST NOT start a process-wide stream ticker. The bouncer SHALL hold a `*lapi.Client` (nil when `crowdsecMode` is `appsec`) and a `*appsec.Client` (nil when AppSec is off). Two bouncers on one Client MAY apply distinct Redis fail-closed values. Two live routers on one Client that disagree on live-cache TTL last-write that TTL into the shared live cache. Per-router LAPI failure action is owned by `core_plugin_lapi_failure-action`; this leaf MUST NOT restate that owner SHALL.

#### Scenario: Second middleware does not start a second ticker
- **WHEN** two live stream configs disagree on update interval and share a LAPI key
- **THEN** one LAPI connection uses the interval from the first `New`
- **AND** the second `New` does not start another ticker

#### Scenario: Appsec mode skips LAPI Open
- **WHEN** `crowdsecMode` is `appsec` and `crowdsecAppsecEnabled` is true
- **THEN** `New` does not reclaim an `lapi.Client`
- **AND** `New` reclaims an `appsec.Client`
- **AND** the bouncer still uses the constructor ctx as the AppSec reclaim holder

#### Scenario: Per-router live TTL last-writes the shared cache
- **WHEN** two live middlewares reclaim the same `lapi.Client` and set different `defaultDecisionSeconds`
- **THEN** each lookup uses the TTL that bouncer passed
- **AND** the shared live cache keeps the last written TTL for that key
