## Purpose

The mock Traefik e2e harness can run two Crowdsec bouncer middlewares in one Traefik process against two LAPI mocks so first-wins sharing is observable as a failure.

## Requirements

### Requirement: Dual-bouncer mock scenario exists
The mock e2e suite SHALL include a scenario that starts one Traefik with two named plugin middlewares and two distinct LAPI mocks. Each router SHALL attach exactly one of those middlewares.

#### Scenario: Ban on A is not ban on B
- **WHEN** the dual-bouncer mock scenario runs
- **AND** LAPI A has a ban for a client IP that LAPI B does not
- **THEN** a request through middleware A is forbidden
- **AND** a request with the same client IP through middleware B is allowed

#### Scenario: First-wins would fail the scenario
- **WHEN** the two middlewares disagree on Crowdsec LAPI host
- **THEN** the scenario still passes only if each router talks to its own LAPI
- **AND** the scenario MUST fail if both routers share one stream or one cache
