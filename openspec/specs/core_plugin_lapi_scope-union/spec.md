## Purpose

How a stream LAPI Client builds `scopes=` from the opener middleware's `crowdsecLapiStreamScopes` plus `ip` and `range`. Subscriber `decisionScopeHeaders` extract request identity only.

## Requirements

### Requirement: Stream poll scopes follow opener list only
In stream or alone mode, the LAPI stream query `scopes=` SHALL include `ip` and `range` plus the opener middleware's `lapiStreamScopes` names (sorted canonical form in SessionHex). Implementations MUST NOT union subscriber `bouncerDecisionScopeHeaders` into the poll. Live and none SHALL continue passing scopes per request from the bouncer's header map via `LiveLookup`. When a bouncer binds to a client whose opener list does not cover keys in its `bouncerDecisionScopeHeaders`, the plugin SHALL log one WARN naming missing scopes (not on every request).

#### Scenario: Opener list country only polls country
- **WHEN** the owner sets `lapiStreamScopes` to `country` and a subscriber maps `username` in `bouncerDecisionScopeHeaders`
- **THEN** stream queries include `country` and do not include `username`
- **AND** the subscriber receives a bind-time scope coverage WARN

#### Scenario: Empty opener list is ip and range only
- **WHEN** `lapiStreamScopes` is omitted or empty
- **THEN** stream queries use `scopes=ip,range` only
