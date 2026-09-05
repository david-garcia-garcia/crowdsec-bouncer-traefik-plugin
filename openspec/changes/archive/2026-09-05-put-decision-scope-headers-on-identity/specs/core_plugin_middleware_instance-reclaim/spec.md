## MODIFIED Requirements

### Requirement: Connection is reclaimed by connection fields not middleware name
`New` SHALL open the process reclaim table with a key derived from Crowdsec connection fields (mode, LAPI/CAPI, redis, update and metrics intervals, AppSec client settings, HTTP timeout, and the **normalized** `decisionScopeHeaders` map). The Traefik middleware name, `next`, ban/captcha templates, trusted IPs, Enabled, and AppSec failure action MUST NOT be in that key. The stored value SHALL be the Crowdsec connection (stream ticker, isolated cache, LAPI HTTP). `New` SHALL return a bouncer that holds `next` and that connection. Client address SHALL come from `pkg/ip.GetRemoteIP`; the connection MUST NOT parse `RemoteAddr`. Empty and omitted `decisionScopeHeaders` SHALL hash as the same identity.

#### Scenario: Same backend two names share one connection
- **WHEN** two `New` calls use the same connection fields and different middleware names, each with a live constructor context
- **THEN** both bouncers use the same connection incarnation
- **AND** only one stream ticker is running for that key

#### Scenario: Different backends are isolated in one process
- **WHEN** two `New` calls use different LAPI hosts (or other connection fields) in one process
- **THEN** two connection incarnations exist
- **AND** a decision present only on the first LAPI remediates only the first bouncer
- **AND** the second bouncer’s cache does not contain that decision

#### Scenario: Different decisionScopeHeaders maps are isolated
- **WHEN** two `New` calls use the same LAPI host and different `decisionScopeHeaders` maps, each with a live constructor context
- **THEN** two connection incarnations exist
- **AND** the bouncers MUST NOT `SameConnection`
