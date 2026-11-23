## MODIFIED Requirements

### Requirement: Stream session is LAPI URL plus bouncer key
For `stream` and `alone`, `SessionHex` SHALL continue to identify the DecisionStore from mode, LAPI scheme/host/path, API key, CAPI credentials, `lapiDefaultDecisionSeconds`, and in stream mode the canonical sorted stream scope list (`ip`, `range`, plus `lapiStreamScopes`). Redis fields SHALL be included in `SessionHex` only when `lapiRedisEnabled` is true; when false, leftover Redis YAML MUST NOT change the store. Inside `pkg/lapi` those values SHALL use local names (`Scheme`, `Host`, `Path`, `Key`, `CapiScenarios`, Redis `Enabled` / `Host` / `ReadHosts` / `Password` / `Database`). The LAPI Client **ownership** reclaim `Open` key SHALL be derived from the Traefik middleware name plus the full LAPI client knob set: mode, scheme, host, path, key, TLS material, `LapiHTTPTimeoutSeconds`, Redis configuration, `lapiStreamScopes`, CAPI machine id and password, `lapiUpdateIntervalSeconds`, `lapiMetricsUpdateIntervalSeconds`, `lapiUpdateMaxFailure`, `lapiCapiScenarios`, and `lapiDefaultDecisionSeconds`. Instance names, `bouncerEnabled`, bounce knobs, and `bouncerDecisionScopeHeaders` MUST NOT be in the ownership key. Two middleware names with identical settings SHALL be two ownership keys and two Clients; they MAY share one DecisionStore when `SessionHex` matches. Stream `scopes=` behavior is owned by `core_plugin_lapi_scope-union`. Live/none ownership keys SHALL include middleware name plus the same client knob family applicable to live/none (including `lapiMetricsUpdateIntervalSeconds` where it splits Clients today) and `lapiUnhealthyBackOffPeriodSecs`. In `stream` and `alone` the ownership payload SHALL carry `0` for `lapiUnhealthyBackOffPeriodSecs`, so a value those modes ignore never opens a new Client. `SessionHex` MUST NOT include `lapiUnhealthyBackOffPeriodSecs`. Changing it in `live` or `none` SHALL Open a new Client with the same `SessionHex`. Changing `lapiUpdateIntervalSeconds`, `lapiMetricsUpdateIntervalSeconds`, `lapiUpdateMaxFailure`, or `lapiCapiScenarios` SHALL Open a new Client with the same `SessionHex` when other store identity fields match. Changing `lapiDefaultDecisionSeconds` SHALL Open a new Client and a new `SessionHex`/store.

#### Scenario: Same SessionHex two middleware names both Open
- **WHEN** two stream owners use different Traefik names, the same LAPI URL and key, and the same scope list and Redis-off settings
- **THEN** both `New` calls succeed
- **AND** two LAPI Client incarnations exist
- **AND** both write the same DecisionStore

#### Scenario: DefaultDecisionSeconds change forks store
- **WHEN** a second Open for the same middleware name changes only `lapiDefaultDecisionSeconds`
- **THEN** the second Open uses a different Client key and a different SessionHex store

#### Scenario: Interval change new Client same store
- **WHEN** a second Open for the same middleware name changes only `lapiUpdateIntervalSeconds`
- **THEN** the second Open uses a different Client key
- **AND** SessionHex matches the first

#### Scenario: Live backoff period change new Client same store
- **WHEN** a second live Open for the same middleware name changes only `lapiUnhealthyBackOffPeriodSecs`
- **THEN** the second Open uses a different Client key
- **AND** SessionHex matches the first

#### Scenario: Stream ignores the backoff period
- **WHEN** a second stream Open for the same middleware name changes only `lapiUnhealthyBackOffPeriodSecs`
- **THEN** the second Open uses the same Client key
