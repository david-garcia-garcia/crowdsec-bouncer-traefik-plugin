## MODIFIED Requirements

### Requirement: Remediation values carry kind then origin
An Ip, header-scope, or Range remediation SHALL start with the ban/captcha/none letter (`t` / `c` / `f`). Range Helper metadata SHALL use `KindOriginString` (kind, then newline, then origin; bare kind when origin is empty). Redis slots SHALL start with those same kind and origin lines; when present, the third line is the raw scenario and the fourth line is the decision end (`core_plugin_decisionstore_store`). Leftover U+001F, `RemediationWithOrigin`, and `RemediationOrigin` MUST NOT exist. `RemediationKind` SHALL live in `pkg/decisionscope` and SHALL return the first letter only. `range-index` stays one key whose records are `cidr=kind` plus an optional origin line. Packed intern ids SHALL NOT appear in that blob. `IsActiveRemediation`, `PreferRemediation`, and request lookup SHALL use that letter. In-process Range membership SHALL return the stored string of the winning CIDR (ban over captcha; if several bans contain the IP, the longest-prefix matching ban). Request lookup SHALL be `Store.LookupRemediation` (memory packed words; Redis slot values). Origin name SHALL be resolved from the DecisionStore intern table only when the winning kind is remediating. The allow-path packed read MUST NOT take a second intern lock. Lookup key *shapes* (client IP, `scope:value`, `range-index`) MUST NOT change; `HeaderScopeKey` and `IPCacheKey` SHALL live in `pkg/decisionstore`. Client address SHALL reuse `pkg/ip.GetRemoteIP` / `clientRequest.remoteIP`. A value that is only the letter SHALL keep matching.

#### Scenario: Newline suffixed ban still remediates
- **WHEN** Redis holds `t` plus a newline and `crowdsec` for the client IP
- **THEN** the request is banned
- **AND** lookup origin is `crowdsec`

#### Scenario: Bare letter still remediates
- **WHEN** the store holds only `t` for the client IP
- **THEN** the request is banned

#### Scenario: Range-index kind plus origin line still remediates
- **WHEN** `range-index` holds `10.0.0.0/8=t` then a newline and `crowdsec` and the client IP is `10.1.2.3`
- **THEN** the request is banned and lookup origin is `crowdsec`

#### Scenario: Bare Range-index kind still remediates
- **WHEN** `range-index` holds only `10.0.0.0/8=t` and the client IP is `10.1.2.3`
- **THEN** the request is banned

#### Scenario: Packed memory IP remediates without leftover
- **WHEN** memory holds a packed ban word for the client IP whose intern id names `crowdsec`
- **THEN** the request is banned
- **AND** a drop resolves origin `crowdsec` from the store table

#### Scenario: Overflow returns kind without origin name
- **WHEN** the store holds a kind-only packed word with origin id `0` for the client IP
- **THEN** the request is remediating for that kind
- **AND** origin name is empty

#### Scenario: Redis value with scenario and end still remediates
- **WHEN** Redis holds `t`, `crowdsec`, `ssh-bf`, and an end line on four lines for the client IP
- **THEN** the request is banned
- **AND** lookup origin is `crowdsec`

### Requirement: Live IP cache slot is the IP query result
When live mode writes a client-address store entry after a LAPI lookup, that entry SHALL be the client-address (`?ip=`) query result only. Header-mapped remediations SHALL stay on the header-scope keys. `LiveLookup` SHALL return `(kind, origin, decision time left, error)` fields and MUST NOT concat-then-split. The time left SHALL be the duration LAPI returned for the decision `preferLiveResult` kept; zero SHALL mean unknown. Memo SHALL be Store Put (same Store as stream; no `liveStore` type). A clean client-address query SHALL write the none payload on the client-address key even when a header-mapped query remediates. A remediating client-address query SHALL write that client-address remediation on the client-address key. When a header-mapped query fails and the merged verdict is not active, the lookup MUST NOT write a none payload on the client-address key.

#### Scenario: Header ban does not land on the IP key
- **WHEN** live mode queries a clean client address and a mapped Country ban `FR`
- **THEN** the client-address store key holds the none payload
- **AND** the Country header-scope key holds the ban
- **AND** `LiveLookup` returns kind ban and origin from the Country decision

#### Scenario: Later header identity does not inherit the ban
- **WHEN** the previous write has happened and a later Store lookup uses the same client address with Country `DE`
- **THEN** that lookup does not remediate from the `FR` ban

#### Scenario: LiveLookup returns the winning decision's duration
- **WHEN** live mode queries a client address that LAPI captchas with duration `10m` and a mapped Country that LAPI bans with duration `2h`
- **THEN** `LiveLookup` returns kind ban and a time left of `2h`
