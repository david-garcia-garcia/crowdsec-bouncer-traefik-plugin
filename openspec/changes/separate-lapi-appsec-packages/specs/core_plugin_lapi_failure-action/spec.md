## MODIFIED Requirements

### Requirement: CrowdsecLapiFailureAction is on the connection identity
Routers that share one LAPI backend SHALL share `crowdsecLapiFailureAction` (it is part of the LAPI reclaim identity with `UpdateMaxFailure`). Two routers MUST NOT disagree on LAPI fallback against one `lapi.Connection`.

#### Scenario: Same LAPI action is shared
- **WHEN** two middlewares reclaim the same `lapi.Connection`
- **THEN** both use the same `crowdsecLapiFailureAction`
