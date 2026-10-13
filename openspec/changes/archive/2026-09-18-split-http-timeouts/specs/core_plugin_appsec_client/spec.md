## ADDED Requirements

### Requirement: AppSec transport Timeout is the effective AppSec seconds
AppSec HTTP construct SHALL set `http.Client.Timeout` and the stored timeout seconds from `config.EffectiveHTTPTimeoutSeconds(config.CrowdsecAppsecHTTPTimeoutSeconds)`. It MUST NOT read raw `HTTPTimeoutSeconds` when the AppSec override is non-zero. `Query` SHALL use that stored client. `AdoptTransport` SHALL keep last-writing that transport on the same Client. AppSec `IdentityHex` and `Key` MUST still omit `HTTPTimeoutSeconds` and `CrowdsecAppsecHTTPTimeoutSeconds`.

#### Scenario: AppSec override adopts Timeout
- **WHEN** a later `New` enables AppSec with the same URL, key, and body limit and `CrowdsecAppsecHTTPTimeoutSeconds` 30
- **THEN** both constructors use the same `appsec.Client` incarnation
- **AND** the stored transport Timeout is 30 seconds

#### Scenario: Query hang honors the AppSec override
- **WHEN** AppSec is opened through `New` or `Open` with `HTTPTimeoutSeconds` 10, `CrowdsecAppsecHTTPTimeoutSeconds` 1, and `crowdsecAppsecFailureAction` passthrough
- **AND** `Query` hits a listener that never accepts
- **THEN** `Query` returns a passthrough allow
- **AND** the call finishes well under 10 seconds

#### Scenario: AppSec timeout knobs do not change Key
- **WHEN** two AppSec configs share URL, key, and body limit and differ only on `HTTPTimeoutSeconds` or `CrowdsecAppsecHTTPTimeoutSeconds`
- **THEN** `Key` and `IdentityHex` are the same
