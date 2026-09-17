## REMOVED Requirements

### Requirement: CrowdsecLapiFailureAction is on the connection identity
**Reason**: Per-router LAPI policy moves onto Bouncer so a failure-action-only reload does not change the reclaim key or create a second Client.
**Migration**: Store `crowdsecLapiFailureAction` on Bouncer via `EffectiveFailureAction`. Delete `Client.LapiFailureAction` and `NewTestLapiFailureActionClient`. Two routers on one Client MAY disagree.

## ADDED Requirements

### Requirement: CrowdsecLapiFailureAction is per-router on Bouncer
Routers that share one LAPI Client SHALL each apply their own `crowdsecLapiFailureAction`. The action MUST NOT be part of LAPI reclaim identity. Two routers MAY disagree on LAPI fallback against one `lapi.Client`. The Client MUST NOT expose a failure-action accessor.

#### Scenario: Two routers disagree on LAPI action
- **WHEN** two middlewares reclaim the same `lapi.Client` and set different `crowdsecLapiFailureAction` values
- **THEN** each router applies its own action on a live LAPI error or stream-unhealthy cache miss

#### Scenario: Failure action is not on Client identity
- **WHEN** two live `New` calls share LAPI URL and key and differ only on `crowdsecLapiFailureAction`
- **THEN** they reclaim the same Client
- **AND** the Client has no failure-action getter
