## MODIFIED Requirements

### Requirement: Bouncer does not own the stream
The per-router bouncer SHALL handle request policy (trusted IPs, ban/captcha pages, whether AppSec runs on pass, LAPI failure action, Redis fail-closed, and live-cache TTL) and MUST NOT start a process-wide stream ticker. The bouncer SHALL Peek named LAPI and AppSec slots on each request (`core_plugin_middleware_named-instance`) and MUST NOT hold `*lapi.Client` or `*appsec.Client` from construct. `lapiEnabled: false` skips LAPI lookup. `appsecEnabled: false` skips AppSec on the pass path. Two bouncing routers on one published Client MAY apply distinct Redis fail-closed values and live-cache TTLs. Exclusive instance-name ownership of the LAPI DecisionStore is owned by `core_plugin_lapi_reclaim-key`.

#### Scenario: AppSec-only skips LAPI Open
- **WHEN** `lapiEnabled` is false and `appsecEnabled` is true with AppSec secrets
- **THEN** `New` does not reclaim an `lapi.Client`
- **AND** `New` reclaims an `appsec.Client` and publishes it

#### Scenario: Per-router live TTL last-writes the shared cache
- **WHEN** two bouncing middlewares Peek the same LAPI Client and set different `bouncerLiveTtlSeconds`
- **THEN** each lookup uses the TTL that bouncer passed
- **AND** the shared live cache keeps the last written TTL for that key

## ADDED Requirements

### Requirement: Holder middleware rejects traffic
When `bouncerHold` is true, `New` SHALL still Open and publish configured clients, and the returned handler SHALL write HTTP 503 without calling `next`. It MUST NOT remediate as a CrowdSec ban (403).

#### Scenario: Hold route returns 503
- **WHEN** `bouncerHold` is true and a request matches that router
- **THEN** the response status is 503
- **AND** `next` is not called
