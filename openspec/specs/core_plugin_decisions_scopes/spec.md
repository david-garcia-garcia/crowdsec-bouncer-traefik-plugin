## Purpose

Match CrowdSec decisions by Ip, Range, and any header-mapped scope so a request is remediating when the client IP sits in a banned CIDR or a configured header matches a Country, AS, or custom scope.

## Requirements

### Requirement: Client IP comes from GetRemoteIP
The bouncer SHALL identify the client IP using the existing remote-IP owner (`pkg/ip.GetRemoteIP`). It MUST NOT parse `RemoteAddr` a second time for decision matching. Stream/alone Range membership SHALL classify the `net.IP` GetRemoteIP already yielded. Range lookup MUST NOT parse the client string.

#### Scenario: Forwarded IP is the lookup address
- **WHEN** Traefik forwards a trusted `X-Forwarded-For` for a banned IP
- **THEN** Ip-scope matching uses that address

#### Scenario: Range membership uses the parsed client IP
- **WHEN** stream has a Range ban `10.0.0.0/8` and GetRemoteIP yielded `10.1.2.3` as `net.IP`
- **THEN** Range matching uses that `net.IP` and MUST NOT parse the client string again

### Requirement: Range decisions match by CIDR containment
When a decision scope is `Range` (any case), the bouncer SHALL treat `value` as a CIDR and remediate a request whose client IP is inside that network. Range membership SHALL be stored on one shared cache key `range-index` as `cidr=remediation` lines so Redis replicas that only read can still match. When several containing CIDRs hit, `ban` SHALL win over `captcha`. In stream and alone modes, the request path SHALL match Range from in-process membership rebuilt from that blob and MUST NOT read `range-index` on the request. live and none SHALL keep skipping `range-index` and expand Range via LAPI `?ip=`.

#### Scenario: Stream Range contains the client
- **WHEN** stream or alone mode has a Range ban `10.0.0.0/8` and the client IP is `10.1.2.3`
- **THEN** the request is forbidden

#### Scenario: IP outside the Range still passes
- **WHEN** only that Range ban exists and the client IP is `203.0.113.10`
- **THEN** the request is allowed

#### Scenario: Redis replica that skipped LAPI still matches Range
- **WHEN** Redis holds a Range ban `10.0.0.0/8` on `range-index` and this instance skipped the stream poll because another instance already updated
- **THEN** a request from `10.1.2.3` is forbidden after this instance hydrates from the blob

#### Scenario: Empty Range membership is a miss
- **WHEN** stream mode has no Range decisions
- **THEN** Range matching does not remediate the request

### Requirement: Header-mapped scopes match configured request headers
Public config `decisionScopeHeaders` SHALL map a CrowdSec scope name to a request header. Empty (the default) SHALL disable header-scope matching. Keys `Ip` and `Range` (any case) SHALL be rejected at config validate. Country values SHALL be ISO 3166-1 alpha-2; `XX` and `T1` SHALL NOT match. AS values SHALL be decimal digits; a leading `AS`/`as` SHALL be stripped. Any other key SHALL match the trimmed header to the stored scope string exactly (`username` is not `user`). A missing or empty header SHALL skip that scope (MUST NOT fail closed). This plugin MUST NOT geolocate.

#### Scenario: Country header matches
- **WHEN** `decisionScopeHeaders.Country` is `CF-IPCountry`, a Country ban `FR` exists, and the request sends `CF-IPCountry: fr`
- **THEN** the request is forbidden

#### Scenario: Placeholder country does not match
- **WHEN** the same Country ban exists and the header is `XX`
- **THEN** the request is allowed

#### Scenario: Custom username scope
- **WHEN** `decisionScopeHeaders.username` is `X-User`, a `username` ban `alice` exists, and the request sends `X-User: alice`
- **THEN** the request is forbidden

#### Scenario: Missing header skips the scope
- **WHEN** a username ban exists and the request has no `X-User`
- **THEN** the request is allowed unless another scope matches

### Requirement: Stream asks LAPI for mapped scopes
The LAPI stream request SHALL include `scopes=ip,range` plus every header scope in the Client live-router union owned by `core_plugin_lapi_scope-union`. This leaf MUST NOT compute `scopes=` from the first constructor’s write-once `decisionScopeHeaders` alone. The CAPI (alone) stream SHALL NOT add a `scopes` query parameter. Live and none SHALL keep `v1/decisions?ip=<clientIP>` and SHALL add `scope` and `value` when a mapped header is present and usable.

#### Scenario: Unmapped Country is not streamed
- **WHEN** every live holder’s `decisionScopeHeaders` is empty
- **THEN** the stream query does not include `country`

#### Scenario: Union includes a joiner’s Country map
- **WHEN** the first live stream router has an empty header map and a later live router on the same Client maps `Country`
- **THEN** a later stream query includes `country`

### Requirement: Ip decisions key on the canonical address
An `Ip` decision SHALL be cached and looked up under one canonical spelling of the address, derived the same way on the store side and on the request side. A decision value that is a `/32` or `/128` CIDR SHALL key on the host address; a value that parses as a bare address SHALL key on `net.IP.String()` of that address, which collapses expanded, upper-case, and IPv4-mapped spellings; a value that parses as neither SHALL be keyed verbatim. The request path SHALL derive that key from the `net.IP` `pkg/ip.GetRemoteIP` already parsed and MUST NOT parse the client address a second time, falling back to the trimmed raw string only when that address did not parse. The store side and the request side MUST NOT be changed independently: a canonical read against a verbatim write is a permanent cache miss. Non-IP scopes MUST NOT be pushed through address parsing.

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
`readRangeIndex` SHALL distinguish a cache miss from a failed read: a miss SHALL be an empty index with no error, and any other cache failure SHALL be returned. `ApplyRangeBatch` SHALL return that error and MUST NOT `Set` or `Delete` `range-index`, because the blob is shared and rebuilding it from an unread base drops every Range decision this poll did not carry. A stream poll whose Range apply failed SHALL be reported as a failed poll, so the stream lease is released and the retry asks for the full decision set.

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

### Requirement: Ban wins across scopes
Decision `type` `ban` and `captcha` SHALL keep their current remediations. Unknown types SHALL be ignored. When several matching scopes exist, `ban` SHALL win over `captcha`.

#### Scenario: Range captcha and Country ban
- **WHEN** the client IP is inside a Range captcha and a mapped Country ban also matches
- **THEN** the request is banned, not captcha

### Requirement: Decision remediations are decisionscope codes
`pkg/decisionscope` SHALL own the ban, captcha, and none cache payloads as `BannedValue` (`t`), `CaptchaValue` (`c`), and `NoBannedValue` (`f`). `RemediationValue` SHALL map LAPI type `ban` to `BannedValue` and `captcha` to `CaptchaValue`. Callers that compare or store a decision remediation SHALL use those names. Wire values MUST remain `t`, `c`, and `f` so existing Redis and memory entries stay valid.

#### Scenario: LAPI ban still stores t
- **WHEN** a decision type is `ban`
- **THEN** the cached remediation is `t`

#### Scenario: LAPI captcha still stores c
- **WHEN** a decision type is `captcha`
- **THEN** the cached remediation is `c`

#### Scenario: None is f
- **WHEN** a live miss or inactive lookup stores a none payload
- **THEN** the cached value is `f`

### Requirement: Stream Range membership hydrates from the shared blob
Each stream or alone connection SHALL rebuild in-process Range membership from `range-index` at stream start and on the stream ticker. A ticker that skips LAPI SHALL still hydrate when the blob changed. Rebuild SHALL use separate ban and captcha CIDR sets so a longer captcha prefix cannot hide a containing ban. Client IP SHALL remain the address already produced by `pkg/ip.GetRemoteIP`.

#### Scenario: First request after stream start uses existing blob
- **WHEN** `range-index` already contains a Range ban `10.0.0.0/8` and a new stream connection starts
- **THEN** a request from `10.1.2.3` is forbidden without waiting for the next stream tick

#### Scenario: Ban wins over a longer captcha prefix
- **WHEN** stream has a Range ban `10.0.0.0/8` and a Range captcha `10.1.0.0/16` and the client IP is `10.1.2.3`
- **THEN** the request is forbidden, not captcha

### Requirement: Matching does not import Traefik config
Cached request lookup SHALL consult Range membership from the membership argument. Nil or empty membership SHALL be a Range miss. The matching package MUST NOT import the Traefik plugin configuration package. Callers MUST NOT pass a Crowdsec-mode flag; live and none leave membership empty because they never hydrate.

#### Scenario: Non-empty membership remediates
- **WHEN** Range membership holds a ban that contains the client IP
- **THEN** the request is remediating from that membership

#### Scenario: Nil membership does not read the blob
- **WHEN** membership is nil and `range-index` holds a Range ban that contains the client IP
- **THEN** Range matching does not remediate from that blob

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
