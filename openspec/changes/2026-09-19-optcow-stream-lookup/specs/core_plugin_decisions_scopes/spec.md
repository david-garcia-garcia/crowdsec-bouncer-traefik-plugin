## ADDED Requirements

### Requirement: Stream and alone request lookup uses the stream store
For stream and alone modes, request remediation lookup SHALL read Ip and header-scope slots from the DecisionStore stream store and SHALL merge them with Range membership supplied by the caller using the same ban-wins rules as cached lookup. Memory backends SHALL Load the published map and probe each present Ip and header key at most once per request. When the Ip probe is an active ban, memory lookup MAY skip Range membership for that request. Redis backends SHALL read Ip and header slots through the owned cache Client (GetInt then Get for leftover strings). Live and none modes SHALL keep using `LookupCachedRemediation` on the cache Client. Lookup key shapes (canonical client IP string, header scope keys) SHALL remain owned by existing Ip and header requirements. Client address SHALL reuse `pkg/ip.GetRemoteIP` / `clientRequest.remoteIP`.

#### Scenario: Memory miss probes without TTL heap
- **WHEN** stream/alone memory has no Ip ban for the client address
- **THEN** lookup completes without reading that Ip key from the TTL heap
- **AND** Range membership is still consulted when Ip is not an active ban

#### Scenario: Memory Ip ban skips Range
- **WHEN** stream/alone memory holds an Ip ban for the client and Range membership would captcha
- **THEN** the merged result is ban

#### Scenario: Redis stream lookup matches cache semantics
- **WHEN** stream/alone Redis holds a packed Ip ban on the cache Client
- **THEN** lookup remediates as ban with origin from the DecisionStore intern table when packed

#### Scenario: Live mode keeps cached lookup
- **WHEN** crowdsec mode is live or none
- **THEN** request lookup does not read the stream store map

## MODIFIED Requirements

### Requirement: Remediation cache values may carry origin
An Ip, header-scope, or Range-index leftover cache value SHALL still start with the ban/captcha/none letter (`t` / `c` / `f`). It MAY append a unit-separator and the metrics origin. Leftover helpers (`RemediationKind`, `RemediationOrigin`, `RemediationWithOrigin`) SHALL live in `pkg/decisionscope`, not `pkg/cache`. `range-index` stays one key whose lines are `cidr=` plus a leftover or bare-letter value and SHALL be written with cache `Set`. Packed intern ids SHALL NOT appear in that blob. `IsActiveRemediation`, `PreferRemediation`, Range index parsing, and request lookup SHALL use that letter. In-process Range membership SHALL return the stored string of the winning CIDR (ban over captcha; if several bans contain the IP, the longest-prefix matching ban). Live/none and Redis stream request lookup SHALL try `GetInt` for packed Ip and header keys and SHALL `Get` the leftover string on miss. Memory stream and alone request lookup SHALL read packed words from the stream store only and MUST NOT call `GetMany` for overflow recovery. Origin name SHALL be resolved from the DecisionStore intern table only when the winning kind is remediating. The allow-path packed read MUST NOT take a second intern lock. Lookup key *shapes* (client IP, `scope:value`, `range-index`) MUST NOT change; the spelling of the client-IP key is owned by "Ip decisions key on the canonical address". Client address SHALL reuse `pkg/ip.GetRemoteIP` / `clientRequest.remoteIP`. A value that is only the letter SHALL keep matching.

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

#### Scenario: Packed memory stream IP remediates without leftover
- **WHEN** memory stream store holds a packed ban word for the client IP whose intern id names `crowdsec`
- **THEN** the request is banned
- **AND** a drop resolves origin `crowdsec` from the store table
- **AND** lookup does not call GetMany for that Ip key

#### Scenario: Memory stream overflow returns kind without origin name
- **WHEN** memory stream store holds a kind-only packed word with origin id `0` for the client IP
- **THEN** the request is remediating for that kind
- **AND** origin name is empty
