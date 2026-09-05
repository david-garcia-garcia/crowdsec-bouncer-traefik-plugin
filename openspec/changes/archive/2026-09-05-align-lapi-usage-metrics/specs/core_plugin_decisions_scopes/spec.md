## ADDED Requirements

### Requirement: Remediation cache values may carry origin
An Ip or header-scope cache value SHALL still start with the ban/captcha/none letter (`t` / `c` / `f`). It MAY append a unit-separator and the metrics origin. `IsActiveRemediation`, `PreferRemediation`, Range index parsing, and request lookup SHALL use that letter. Lookup keys (client IP, `scope:value`, `range-index`) MUST NOT change. A value that is only the letter (today’s Redis) SHALL keep matching.

#### Scenario: Suffixed ban still remediates
- **WHEN** cache holds `t` plus a unit-separator and `crowdsec` for the client IP
- **THEN** the request is banned

#### Scenario: Bare letter still remediates
- **WHEN** cache holds only `t` for the client IP
- **THEN** the request is banned
