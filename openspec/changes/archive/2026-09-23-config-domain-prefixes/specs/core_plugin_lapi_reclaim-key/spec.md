## ADDED Requirements

### Requirement: Reclaim identity JSON reuses the LAPI marshalers
LAPI reclaim identity and ownership JSON SHALL be produced only by the marshalers in `pkg/lapi/identity.go` (`identity` and `ownership`). Implementations MUST NOT reconstruct that payload in `pkg/configuration` or `pkg/bouncer`. Inside those marshalers the JSON SHALL drop the redundant `lapi` prefix (`scheme`, `host`, `path`, `key`) to match AppSec, SHALL name TLS client material `tlsClientCertificate` / `tlsClientKey`, and SHALL drop public `lapi` / `crowdsec` syllables from Redis and CAPI fields (`capiScenarios`, Redis `enabled` / `host` / `readHosts` / `password` / `database`). A field-name change SHALL change the hash. A process restart SHALL build a new Client. Unmeasured in-process reclaim without restart is out of scope.

#### Scenario: Ownership hash uses identity.go only
- **WHEN** two Opens share middleware name and LAPI knobs
- **THEN** both ownership keys come from `pkg/lapi/identity.go`
- **AND** no second hash is computed in `configuration` or `bouncer`

#### Scenario: LAPI JSON matches AppSec shape
- **WHEN** the identity marshaler encodes scheme, host, path, and key
- **THEN** the JSON field names are `scheme`, `host`, `path`, and `key`
- **AND** they are not `lapiScheme` / `lapiHost` / `lapiPath` / `lapiKey`

## MODIFIED Requirements

### Requirement: Stream session is LAPI URL plus bouncer key
For `stream` and `alone`, `SessionHex` SHALL continue to identify the DecisionStore from mode, LAPI scheme/host/path, API key, CAPI credentials, `lapiDefaultDecisionSeconds`, and in stream mode the canonical sorted stream scope list (`ip`, `range`, plus `lapiStreamScopes`). Redis fields SHALL be included in `SessionHex` only when `lapiRedisEnabled` is true; when false, leftover Redis YAML MUST NOT change the store. Inside `pkg/lapi` those values SHALL use local names (`Scheme`, `Host`, `Path`, `Key`, `CapiScenarios`, Redis `Enabled` / `Host` / `ReadHosts` / `Password` / `Database`). The LAPI Client **ownership** reclaim `Open` key SHALL be derived from the Traefik middleware name plus the full LAPI client knob set: mode, scheme, host, path, key, TLS material, `LapiHTTPTimeoutSeconds`, Redis configuration, `lapiStreamScopes`, CAPI machine id and password, `lapiUpdateIntervalSeconds`, `lapiMetricsUpdateIntervalSeconds`, `lapiUpdateMaxFailure`, `lapiCapiScenarios`, and `lapiDefaultDecisionSeconds`. `bouncerStartupBlock`, instance names, `bouncerEnabled`, bounce knobs, and `bouncerDecisionScopeHeaders` MUST NOT be in the ownership key. Two middleware names with identical settings SHALL be two ownership keys and two Clients; they MAY share one DecisionStore when `SessionHex` matches. Stream `scopes=` behavior is owned by `core_plugin_lapi_scope-union`. Live/none ownership keys SHALL include middleware name plus the same client knob family applicable to live/none (including `lapiMetricsUpdateIntervalSeconds` where it splits Clients today). Changing `lapiUpdateIntervalSeconds`, `lapiMetricsUpdateIntervalSeconds`, `lapiUpdateMaxFailure`, or `lapiCapiScenarios` SHALL Open a new Client with the same `SessionHex` when other store identity fields match. Changing `lapiDefaultDecisionSeconds` SHALL Open a new Client and a new `SessionHex`/store.

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

### Requirement: Inherit HTTP timeout knobs stay out of LAPI store identity
`SessionHex` MUST NOT include `LapiHTTPTimeoutSeconds`, `AppsecHTTPTimeoutSeconds`, or `BouncerCaptchaSiteverifyHTTPTimeoutSeconds`. The LAPI ownership Open key SHALL include `LapiHTTPTimeoutSeconds` (the stored knob, not an inherited effective value). AppSec and captcha timeout knobs MUST NOT enter the LAPI ownership key. Implementations MUST NOT add a second timeout hash beside `pkg/lapi/identity.go`.

#### Scenario: Timeout knobs do not change SessionHex
- **WHEN** two stream configs share LAPI URL, key, and Redis store parameters and differ only on `lapiHttpTimeoutSeconds`
- **THEN** `SessionHex` is the same
- **AND** the LAPI ownership keys differ
