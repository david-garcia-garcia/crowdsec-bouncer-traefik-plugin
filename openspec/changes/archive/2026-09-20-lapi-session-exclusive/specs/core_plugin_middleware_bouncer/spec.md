## MODIFIED Requirements

### Requirement: Bouncer does not own the stream
The per-router bouncer SHALL handle request policy (trusted IPs, ban/captcha pages, whether AppSec runs on pass, LAPI failure action, Redis fail-closed, and live-cache TTL) and MUST NOT start a process-wide stream ticker. The bouncer SHALL hold a `*lapi.Client` (nil when `crowdsecMode` is `appsec`) and a `*appsec.Client` (nil when AppSec is off). Two bouncers on one Client MAY apply distinct Redis fail-closed values. Two live routers on one Client that disagree on live-cache TTL last-write that TTL into the shared live cache. Per-router LAPI failure action is owned by `core_plugin_lapi_failure-action`; this leaf MUST NOT restate that owner SHALL. Exclusive Traefik-name ownership of the LAPI DecisionStore is owned by `core_plugin_lapi_reclaim-key`; this leaf MUST NOT invent a second identity registry.

#### Scenario: Second middleware does not start a second ticker
- **WHEN** two live stream configs use the same Traefik name, disagree on update interval, and share a LAPI key
- **THEN** one LAPI connection uses the interval from the first `New`
- **AND** the second `New` does not start another ticker

#### Scenario: Appsec mode skips LAPI Open
- **WHEN** `crowdsecMode` is `appsec` and `crowdsecAppsecEnabled` is true
- **THEN** `New` does not reclaim an `lapi.Client`
- **AND** `New` reclaims an `appsec.Client`
- **AND** the bouncer still holds that AppSec incarnation through a reclaim context derived from the constructor ctx

#### Scenario: Per-router live TTL last-writes the shared cache
- **WHEN** two live middlewares reclaim the same `lapi.Client` and set different `defaultDecisionSeconds`
- **THEN** each lookup uses the TTL that bouncer passed
- **AND** the shared live cache keeps the last written TTL for that key

## ADDED Requirements

### Requirement: A second different Traefik name fails New
When `crowdsecMode` is live, stream, or none (not `appsec`), `New` SHALL fail if a DecisionStore for that LAPI session already exists with a different `createdBy` (`core_plugin_lapi_reclaim-key`). Same Traefik name on many routers MUST still share. Failed `New` SHALL still release bindCtx. AppSec Open is unchanged.

#### Scenario: Different Traefik name on the same LAPI key fails New
- **WHEN** a live stream middleware named `foo` already holds the DecisionStore for a LAPI URL and key
- **AND** a later `New` for that same LAPI URL and key uses Traefik name `bar`
- **THEN** `New` returns an error
- **AND** bindCtx is released
- **AND** the first middleware’s store and Client stay held
