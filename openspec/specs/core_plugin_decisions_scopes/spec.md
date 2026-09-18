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
When a decision scope is `Range` (any case), the bouncer SHALL treat `value` as a CIDR and remediate a request whose client IP is inside that network. A parseable bare IP SHALL be stored as that host `/32` (IPv4) or `/128` (IPv6) on range-index upsert and remove so write and delete pair. Membership rebuild SHALL use `ParseCIDR` only; a leftover bare-IP index line SHALL be skipped. Range membership SHALL be stored on one shared cache key `range-index` as `cidr=remediation` lines so Redis replicas that only read can still match. When several containing CIDRs hit, `ban` SHALL win over `captcha`. In stream and alone modes, the request path SHALL match Range from in-process membership rebuilt from that blob and MUST NOT read `range-index` on the request. live and none SHALL keep skipping `range-index` and expand Range via LAPI `?ip=`.

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

#### Scenario: Bare Range host remediates that address
- **WHEN** stream or alone mode has a Range ban `192.0.2.1` and the client IP is `192.0.2.1`
- **THEN** the request is forbidden

#### Scenario: Leftover bare Range line does not remediate
- **WHEN** `range-index` holds `192.0.2.1=t` and the client IP is `192.0.2.1`
- **THEN** the request is allowed

#### Scenario: Delete of LAPI host drops the rewritten prefix
- **WHEN** stream stored Range `192.0.2.1` as `192.0.2.1/32` and then deletes Range `192.0.2.1`
- **THEN** that host is no longer remediating

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
An `Ip` decision SHALL be cached and looked up under one canonical spelling of the address. The store path SHALL key a decision value that is a `/32` or `/128` CIDR on the host address; a value that parses as a bare address SHALL key on `net.IP.String()` of that address, which collapses expanded, upper-case, and IPv4-mapped spellings; a value that parses as neither SHALL be keyed verbatim. After `GetRemoteIP` yields a parsed address, `clientRequest.remoteIP` SHALL be that address's `net.IP.String()` and the request path SHALL look up the Ip slot under that string. It MUST NOT re-parse the client address and MUST NOT use a second request-path key helper. Until that parse succeeds, `remoteIP` SHALL stay the raw extracted text so extract-fail and unparseable-address remediations can log it. Live-mode memo SHALL write under that same canonical `remoteIP` and MUST NOT re-derive a key from the raw header. Captcha gate bind SHALL compare that same canonical `remoteIP`. The store side and the request side MUST NOT be changed independently: a canonical read against a verbatim write is a permanent cache miss. Non-IP scopes MUST NOT be pushed through address parsing.

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

#### Scenario: Real CrowdSec Ip ban matches a different request spelling in none mode
- **WHEN** a live LAPI holds an Ip ban whose value is an expanded IPv6, an upper-case IPv6, or an IPv4-mapped address, and Traefik is hit in none mode with a different spelling of that same address on the forwarded header
- **THEN** the request is forbidden

#### Scenario: Real CrowdSec Ip ban matches a different request spelling in stream mode
- **WHEN** a live LAPI holds an Ip ban whose value is an expanded IPv6, an upper-case IPv6, or an IPv4-mapped address, and Traefik is hit in stream mode with a different spelling of that same address on the forwarded header
- **THEN** the request is forbidden after the stream poll applies the decision

#### Scenario: Captcha gate bind uses the canonical remoteIP
- **WHEN** captcha grace is bound to the client address and a later request arrives with a different spelling of the same address
- **THEN** the gate cookie still matches

#### Scenario: Unparseable address keeps the raw remoteIP
- **WHEN** `GetRemoteIP` returns raw header text and a nil parsed address
- **THEN** the request is remediating as an unparseable-address failure and the raw text is what the failure log shows

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

### Requirement: Lookup resolves origin only on drop
Cached request lookup SHALL return the winning remediation kind without resolving the usage-metrics origin name on the allow path. Kind SHALL come from a shift/mask of a packed memory word or from the first letter of a leftover string. Origin name resolve (`table[id]` or the leftover U+001F suffix) SHALL run only when the bouncer reports a drop (`IncDropped`) or when usage-metrics needs the label. A letter-only value SHALL keep matching and MAY omit origin on drop.

#### Scenario: Packed hit still bans without a name on the allow path
- **WHEN** stream memory holds a packed Ip ban for the client IP
- **THEN** the request is banned
- **AND** the intern table is consulted for the origin name only when that drop is counted

#### Scenario: Letter-only still remediates
- **WHEN** cache holds only `t` for the client IP
- **THEN** the request is banned and the dropped item MAY omit `origin`

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

### Requirement: Range index upsert and remove match the same network
`upsertIndexCIDR` and `removeCIDRFromIndex` SHALL treat two CIDR strings as the same `range-index` line when both parse as IP networks and the parsed network addresses are equal and the prefix lengths match (mask ones and bits). They MUST NOT compare `ParseCIDR`'s first (unmasked) IP. When either side fails to parse, they SHALL fall back to raw-text equality so identical unparseable lines still match. A same-network hit SHALL replace or drop every matching line. A replace or append SHALL persist the incoming CIDR text and MUST NOT rewrite that line to `(*net.IPNet).String()`. This leaf MUST NOT sweep-rewrite leftover spellings the call did not name. `ApplyRangeBatch` SHALL keep one read, removals then upserts, and one write; a failed GET that is not a miss SHALL still return and MUST NOT write.

#### Scenario: Different spelling of the same network is removed
- **WHEN** `AddRange` stores `10.1.2.0/8` as a ban and `RemoveRange` is called with `10.0.0.0/8`
- **THEN** `range-index` no longer holds that network
- **AND** membership for `10.1.2.3` is clear

#### Scenario: Same-network upsert persists the incoming spelling
- **WHEN** `range-index` holds `10.1.2.0/8=c` and `AddRange` upserts `10.0.0.0/8` as a ban
- **THEN** that line is replaced with the incoming text `10.0.0.0/8` plus the new remediation
- **AND** leftover lines this call did not name are left as they were

#### Scenario: Identical unparseable text still matches
- **WHEN** `range-index` holds an unparseable CIDR line and remove is called with that same raw text
- **THEN** that line is dropped

#### Scenario: Parseable and unparseable text are not the same line
- **WHEN** `range-index` holds `10.0.0.0/8=t` and remove is called with unparseable text that is not that string
- **THEN** the `10.0.0.0/8` line stays
