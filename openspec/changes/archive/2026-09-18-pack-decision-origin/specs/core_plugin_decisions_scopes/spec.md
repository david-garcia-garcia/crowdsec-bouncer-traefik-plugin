## ADDED Requirements

### Requirement: Lookup resolves origin only on drop
Cached request lookup SHALL return the winning remediation kind without resolving the usage-metrics origin name on the allow path. Kind SHALL come from a shift/mask of a packed memory word or from the first letter of a leftover string. Origin name resolve (`table[id]` or the leftover U+001F suffix) SHALL run only when the bouncer reports a drop (`IncDropped`) or when usage-metrics needs the label. A letter-only value SHALL keep matching and MAY omit origin on drop.

#### Scenario: Packed hit still bans without a name on the allow path
- **WHEN** stream memory holds a packed Ip ban for the client IP
- **THEN** the request is banned
- **AND** the intern table is consulted for the origin name only when that drop is counted

#### Scenario: Letter-only still remediates
- **WHEN** cache holds only `t` for the client IP
- **THEN** the request is banned and the dropped item MAY omit `origin`

## MODIFIED Requirements

### Requirement: Remediation cache values may carry origin
An Ip, header-scope, or Range-index cache value SHALL still identify the ban/captcha/none letter (`t` / `c` / `f`). On Redis, live/none, and overflow, it MAY append a unit-separator and the metrics origin. On stream/alone memory, an interned value MAY be a packed kind-plus-origin-id word instead of that suffix (`core_cache_client_origin-dictionary`). `range-index` stays one key whose lines are `cidr=` plus the backend's stored form. `IsActiveRemediation`, `PreferRemediation`, Range index parsing, and request lookup SHALL use that letter. In-process Range membership SHALL return the stored value of the winning CIDR (ban over captcha; if several bans contain the IP, the longest-prefix matching ban). Lookup key *shapes* (client IP, `scope:value`, `range-index`) MUST NOT change; the spelling of the client-IP key is owned by "Ip decisions key on the canonical address". A value that is only the letter (today's Redis) SHALL keep matching.

#### Scenario: Suffixed ban still remediates
- **WHEN** cache holds `t` plus a unit-separator and `crowdsec` for the client IP
- **THEN** the request is banned

#### Scenario: Bare letter still remediates
- **WHEN** cache holds only `t` for the client IP
- **THEN** the request is banned

#### Scenario: Suffixed Range-index line still remediates
- **WHEN** `range-index` holds `10.0.0.0/8=` plus `t` plus a unit-separator and `crowdsec` and the client IP is `10.1.2.3`
- **THEN** the request is banned and lookup origin is `crowdsec` when that drop is counted

#### Scenario: Bare Range-index letter still remediates
- **WHEN** `range-index` holds only `10.0.0.0/8=t` and the client IP is `10.1.2.3`
- **THEN** the request is banned

#### Scenario: Packed memory ban still remediates
- **WHEN** stream memory holds a packed kind-plus-origin-id ban for the client IP
- **THEN** the request is banned
