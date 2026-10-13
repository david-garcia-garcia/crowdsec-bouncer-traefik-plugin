## ADDED Requirements

### Requirement: Live IP cache slot is the IP query result
When live mode writes a client-address cache entry after a LAPI lookup, that entry SHALL be the client-address (`?ip=`) query result only. Header-mapped remediations SHALL stay on the header-scope cache keys that already store each mapped header result. The client-address key SHALL be the address `pkg/ip.GetRemoteIP` already chose and that the live lookup received; this leaf MUST NOT parse `RemoteAddr` or walk forwarded headers again. Header identity SHALL be the map `decisionscope.RequestScopeValues` already produced; this leaf MUST NOT re-read request headers to decide the IP-slot write.

A clean client-address query SHALL write the none payload (`NoBannedValue`) on the client-address key even when a header-mapped query remediates. The request that just merged SHALL still return that header remediation. A remediating client-address query SHALL write that client-address remediation on the client-address key even when a header-mapped query also remediates. Captcha is an active remediation; this leaf MUST NOT split a captcha-only write path.

When a header-mapped query fails and the merged verdict is not active, the lookup MUST NOT write a none payload on the client-address key (the fail-closed rule owned by `core_plugin_lapi_failure-action`).

A later cache lookup for the same client address and a different header identity MUST NOT inherit the first identity's header remediation from the client-address key.

#### Scenario: Header ban does not land on the IP key
- **WHEN** live mode queries a clean client address and a mapped Country ban `FR`
- **THEN** the client-address cache key holds the none payload
- **AND** the Country header-scope key holds the ban
- **AND** the lookup that just merged still remediates as a ban

#### Scenario: Later header identity does not inherit the ban
- **WHEN** the previous write has happened and a later cache lookup uses the same client address with Country `DE`
- **THEN** that lookup does not remediate from the `FR` ban

#### Scenario: IP ban stays on the IP key
- **WHEN** live mode queries a banned client address and a mapped Country ban
- **THEN** the client-address cache key holds the IP ban
- **AND** the Country header-scope key holds the Country ban
