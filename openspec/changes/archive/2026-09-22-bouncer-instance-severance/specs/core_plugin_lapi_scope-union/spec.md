## REMOVED Requirements

### Requirement: Stream scopes are the live-router union
**Reason**: Stream poll scopes come from opener `crowdsecLapiStreamScopes` only; bouncers no longer register header maps on OpenStream.
**Migration**: Move scope names to the LAPI owner middleware's `crowdsecLapiStreamScopes`; keep `decisionScopeHeaders` on bouncers for request extraction only.

### Requirement: Growing the union does not send startup=true
**Reason**: Union registry removed.
**Migration**: Scope list changes are a new SessionHex store via opener list change.

### Requirement: Shrinking the union does not sweep cache keys
**Reason**: Union registry removed.
**Migration**: Stale keys expire via TTL or store incarnation as today.

## ADDED Requirements

### Requirement: Stream poll scopes follow opener list only
In stream or alone mode, the LAPI stream query `scopes=` SHALL include `ip` and `range` plus the opener middleware's `crowdsecLapiStreamScopes` names (sorted canonical form in SessionHex). Implementations MUST NOT union subscriber `decisionScopeHeaders` into the poll. Live and none SHALL continue passing scopes per request from the bouncer's header map via `LiveLookup`. When a bouncer binds to a client whose opener list does not cover keys in its `decisionScopeHeaders`, the plugin SHALL log one WARN naming missing scopes (not on every request).

#### Scenario: Opener list country only polls country
- **WHEN** the owner sets `crowdsecLapiStreamScopes` to `country` and a subscriber maps `username` in `decisionScopeHeaders`
- **THEN** stream queries include `country` and do not include `username`
- **AND** the subscriber receives a bind-time scope coverage WARN

#### Scenario: Empty opener list is ip and range only
- **WHEN** `crowdsecLapiStreamScopes` is omitted or empty
- **THEN** stream queries use `scopes=ip,range` only
