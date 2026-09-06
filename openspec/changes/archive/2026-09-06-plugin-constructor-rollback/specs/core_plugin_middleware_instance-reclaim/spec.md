## MODIFIED Requirements

### Requirement: Constructor rollback on partial failure
When `New` opens a reclaimed LAPI or AppSec backend and a later step in the same `New` call returns an error, the plugin SHALL release every reclaim holder opened in that call before returning. The release MUST NOT depend on Traefik canceling the constructor context.

#### Scenario: AppSec failure after LAPI open
- **WHEN** `New` successfully opens LAPI for a live or stream config
- **AND** AppSec open fails because TLS material is invalid
- **THEN** `New` returns a non-nil error
- **AND** the LAPI reclaim slot has zero holders

#### Scenario: Successful New keeps holder on constructor context
- **WHEN** `New` completes without error
- **THEN** reclaim holders opened in that call remain bound until Traefik cancels the constructor context

### Requirement: Appsec mode requires AppSec enabled
When `crowdsecMode` is `appsec`, `New` SHALL require `crowdsecAppsecEnabled: true` and MUST NOT return a pass-through bouncer with neither LAPI nor AppSec enforcement.

#### Scenario: Appsec mode without AppSec enabled is rejected
- **WHEN** `crowdsecMode` is `appsec` and `crowdsecAppsecEnabled` is false
- **THEN** `New` returns a non-nil error
- **AND** no reclaim holder is created for that call

#### Scenario: Appsec-only with AppSec enabled
- **WHEN** `crowdsecMode` is `appsec` and `crowdsecAppsecEnabled` is true with valid AppSec listener settings
- **THEN** `New` does not reclaim an `lapi.Client`
- **AND** `New` reclaims an `appsec.Client`
