## REMOVED Requirements

### Requirement: Exclusive Traefik name owns the DecisionStore session
**Reason**: Multiple middleware names may share one SessionHex DecisionStore when ownership Open keys differ; slot collision governs named publish conflicts.
**Migration**: Use named instance slots; do not rely on `createdBy` Peek failure for a second Traefik name.

## MODIFIED Requirements

### Requirement: Stream session is LAPI URL plus bouncer key
For `stream` and `alone`, `SessionHex` SHALL continue to identify the DecisionStore from mode, LAPI scheme/host/path, API key, CAPI credentials, `defaultDecisionSeconds`, and in stream mode the canonical sorted stream scope list (`ip`, `range`, plus `crowdsecLapiStreamScopes`). Redis fields SHALL be included in `SessionHex` only when `redisCacheEnabled` is true; when false, leftover Redis YAML MUST NOT change the store. The LAPI Client **ownership** reclaim `Open` key SHALL be derived from the Traefik middleware name plus the full LAPI client knob set: mode, scheme, host, path, key, TLS material, effective HTTP timeout, Redis configuration, `crowdsecLapiStreamScopes`, CAPI machine id and password, `updateIntervalSeconds`, `metricsUpdateIntervalSeconds`, `updateMaxFailure`, `crowdsecCapiScenarios`, and `defaultDecisionSeconds`. `streamStartupBlock`, instance names, `enabled`, bounce knobs, and `decisionScopeHeaders` MUST NOT be in the ownership key. Two middleware names with identical settings SHALL be two ownership keys and two Clients; they MAY share one DecisionStore when `SessionHex` matches. Stream `scopes=` behavior is owned by `core_plugin_lapi_scope-union`. Live/none ownership keys SHALL include middleware name plus the same client knob family applicable to live/none (including `metricsUpdateIntervalSeconds` where it splits Clients today). Changing `updateIntervalSeconds`, `metricsUpdateIntervalSeconds`, `updateMaxFailure`, or `crowdsecCapiScenarios` SHALL Open a new Client with the same `SessionHex` when other store identity fields match. Changing `defaultDecisionSeconds` SHALL Open a new Client and a new `SessionHex`/store.

#### Scenario: Same SessionHex two middleware names both Open
- **WHEN** two stream owners use different Traefik names, the same LAPI URL and key, and the same scope list and Redis-off settings
- **THEN** both `New` calls succeed
- **AND** two LAPI Client incarnations exist
- **AND** both write the same DecisionStore

#### Scenario: DefaultDecisionSeconds change forks store
- **WHEN** a second Open for the same middleware name changes only `defaultDecisionSeconds`
- **THEN** the second Open uses a different Client key and a different SessionHex store

#### Scenario: Interval change new Client same store
- **WHEN** a second Open for the same middleware name changes only `updateIntervalSeconds`
- **THEN** the second Open uses a different Client key
- **AND** SessionHex matches the first

### Requirement: Snapshot change while sleeping opens a new reclaim key
When no live holder remains for an ownership key and grace has not ended, a `New` with the **same** middleware name and the **same** ownership key SHALL Wake that Client. A `New` with a **different** ownership key (any listed knob change, including Redis toggle or scope list change) SHALL Open a new Client; the sleeping prior Client SHALL not receive Wake. Redis host or scope list change while sleeping SHALL NOT overlap stream pollers on the old store when the old ticker was Sleep'd.

#### Scenario: Same ownership key reload Wakes
- **WHEN** every holder for ownership key K is cancelled and a `New` with the same middleware name and K runs before grace ends
- **THEN** the same Client incarnation is returned
- **AND** stream polling resumes with `startup=false` when the store was warm

## ADDED Requirements

### Requirement: Duplicate stream owners same host and key warn
When two stream or alone owners use the same LAPI host and API key with distinct middleware names, both `New` calls SHALL succeed. The second Open SHALL log one WARN `crowdsec lapi stream collision` naming both middleware names and the host (not the API key). Live and none modes SHALL NOT emit this warning.

#### Scenario: Collision warn does not fail New
- **WHEN** two stream-enabled owners share host and API key
- **THEN** both routes may serve
- **AND** the WARN line appears in Traefik logs
