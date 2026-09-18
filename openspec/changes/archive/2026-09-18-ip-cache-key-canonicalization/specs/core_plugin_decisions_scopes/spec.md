## MODIFIED Requirements

### Requirement: Ip decisions key on the canonical address
An `Ip` decision SHALL be cached and looked up under one canonical spelling of the address, derived
the same way on the store side and on the request side. A decision value that is a `/32` or `/128`
CIDR SHALL key on the host address; a value that parses as a bare address SHALL key on
`net.IP.String()` of that address, which collapses expanded, upper-case, and IPv4-mapped spellings; a
value that parses as neither SHALL be keyed verbatim. The request path SHALL derive that key from the
`net.IP` `pkg/ip.GetRemoteIP` already parsed and MUST NOT parse the client address a second time,
falling back to the trimmed raw string only when that address did not parse. The store side and the
request side MUST NOT be changed independently: a canonical read against a verbatim write is a
permanent cache miss. Non-IP scopes MUST NOT be pushed through address parsing.

#### Scenario: Bare IP ban still works
- **WHEN** an Ip ban exists for the client IP
- **THEN** the request is forbidden

#### Scenario: Expanded IPv6 decision matches a compressed request
- **WHEN** the stream stored an Ip ban whose value is `2001:0db8:0000:0000:0000:0000:0000:0001` and the request address is `2001:db8::1`
- **THEN** the request is forbidden

#### Scenario: Upper-case IPv6 decision matches a lower-case request
- **WHEN** the stream stored an Ip ban whose value is `2001:DB8::1` and the request address is `2001:db8::1`
- **THEN** the request is forbidden

#### Scenario: IPv4-mapped and dotted forms share one slot
- **WHEN** the stream stored an Ip ban whose value is `::ffff:192.0.2.4` and the request address is `192.0.2.4`, or the reverse
- **THEN** the request is forbidden

#### Scenario: Live-mode memo still hits on a repeated request
- **WHEN** live mode answers a request from an address spelled `2001:DB8::1` and four more requests arrive from that same address inside the live-cache TTL
- **THEN** LAPI is queried once, not once per request

#### Scenario: Country value is not an address
- **WHEN** a Country decision carries the value `fr`
- **THEN** it is keyed as the normalized header scope `country:FR` and is not parsed as an address

### Requirement: Range index apply does not write from an index it could not read
`readRangeIndex` SHALL distinguish a cache miss from a failed read: a miss SHALL be an empty index
with no error, and any other cache failure SHALL be returned. `ApplyRangeBatch` SHALL return that
error and MUST NOT `Set` or `Delete` `range-index`, because the blob is shared and rebuilding it from
an unread base drops every Range decision this poll did not carry. A stream poll whose Range apply
failed SHALL be reported as a failed poll, so the stream lease is released and the retry asks for the
full decision set.

#### Scenario: Unreachable read preserves the shared index
- **WHEN** `Get(range-index)` answers `cache:unreachable` — for example a `redisCacheReadHosts` replica is down while the writer is healthy — and a poll would upsert a new Range CIDR
- **THEN** `ApplyRangeBatch` returns the error and the stored `range-index` still holds the CIDRs it held before

#### Scenario: Unreachable read does not delete the shared index
- **WHEN** the same read fails and the poll carries only Range removals
- **THEN** `range-index` is not deleted

#### Scenario: Cache miss still applies
- **WHEN** `Get(range-index)` answers `cache:miss` and the poll upserts `10.0.0.0/8`
- **THEN** `range-index` is written with that line

#### Scenario: A failed range apply releases the stream lease
- **WHEN** a stream poll won the `updated` lease and its Range apply could not read the index
- **THEN** the poll reports the failure, the lease key is dropped, and the connection stays in startup so the next query asks for the full set

### Requirement: Remediation cache values may carry origin
An Ip, header-scope, or Range-index cache value SHALL still start with the ban/captcha/none letter (`t` / `c` / `f`). It MAY append a unit-separator and the metrics origin. `range-index` stays one key whose lines are `cidr=` plus that value. `IsActiveRemediation`, `PreferRemediation`, Range index parsing, and request lookup SHALL use that letter. In-process Range membership SHALL return the stored string of the winning CIDR (ban over captcha; if several bans contain the IP, the longest-prefix matching ban). Lookup key *shapes* (client IP, `scope:value`, `range-index`) MUST NOT change; the spelling of the client-IP key is owned by "Ip decisions key on the canonical address". A value that is only the letter (today’s Redis) SHALL keep matching.

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
