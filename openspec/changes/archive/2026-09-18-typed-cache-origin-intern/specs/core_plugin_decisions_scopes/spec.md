## MODIFIED Requirements

### Requirement: Remediation cache values may carry origin
An Ip, header-scope, or Range-index leftover cache value SHALL still start with the ban/captcha/none letter (`t` / `c` / `f`). It MAY append a unit-separator and the metrics origin. Leftover helpers (`RemediationKind`, `RemediationOrigin`, `RemediationWithOrigin`) SHALL live in `pkg/decisionscope`, not `pkg/cache`. Packed memory Range-index lines SHALL be the letter plus the decimal intern id (no unit-separator). `range-index` stays one key whose lines are `cidr=` plus that leftover or packed value and SHALL be written with cache `Set`, never `SetInt`. `IsActiveRemediation`, `PreferRemediation`, Range index parsing, and request lookup SHALL use that letter. In-process Range membership SHALL return the stored string of the winning CIDR (ban over captcha; if several bans contain the IP, the longest-prefix matching ban). Request lookup SHALL try `GetInt` for packed memory Ip and header keys and SHALL `Get` the leftover string on miss. Origin name SHALL be resolved from the DecisionStore intern table only when the winning kind is remediating. The allow-path `GetInt` MUST NOT take a second intern lock. Lookup key *shapes* (client IP, `scope:value`, `range-index`) MUST NOT change; the spelling of the client-IP key is owned by "Ip decisions key on the canonical address". Client address SHALL reuse `pkg/ip.GetRemoteIP` / `clientRequest.remoteIP`. A value that is only the letter SHALL keep matching.

#### Scenario: Suffixed ban still remediates
- **WHEN** cache holds `t` plus a unit-separator and `crowdsec` for the client IP
- **THEN** the request is banned

#### Scenario: Bare letter still remediates
- **WHEN** cache holds only `t` for the client IP
- **THEN** the request is banned

#### Scenario: Suffixed Range-index line still remediates
- **WHEN** `range-index` holds `10.0.0.0/8=` plus `t` plus a unit-separator and `crowdsec` and the client IP is `10.1.2.3`
- **THEN** the request is banned and lookup origin is `crowdsec`

#### Scenario: Bare Range-index letter still remediates
- **WHEN** `range-index` holds only `10.0.0.0/8=t` and the client IP is `10.1.2.3`
- **THEN** the request is banned

#### Scenario: Packed memory IP remediates without leftover
- **WHEN** memory cache GetInt of the client IP returns a packed ban word whose intern id names `crowdsec`
- **THEN** the request is banned
- **AND** a drop resolves origin `crowdsec` from the store table
- **AND** an allow-path GetInt for a none word does not call OriginName
