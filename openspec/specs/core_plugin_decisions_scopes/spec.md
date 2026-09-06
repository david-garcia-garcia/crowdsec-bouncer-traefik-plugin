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
The LAPI stream request SHALL include `scopes=ip,range` plus every mapped header scope. The CAPI (alone) stream SHALL NOT add a `scopes` query parameter. Live and none SHALL keep `v1/decisions?ip=<clientIP>` and SHALL add `scope` and `value` when a mapped header is present and usable.

#### Scenario: Unmapped Country is not streamed
- **WHEN** `decisionScopeHeaders` is empty
- **THEN** the stream query does not include `country`

### Requirement: Ip decisions stay exact-address keys
An `Ip` decision SHALL be cached and looked up by the client IP. If the decision value is a `/32` or `/128` CIDR, the bouncer SHALL store the host address.

#### Scenario: Bare IP ban still works
- **WHEN** an Ip ban exists for the client IP
- **THEN** the request is forbidden

### Requirement: Ban wins across scopes
Decision `type` `ban` and `captcha` SHALL keep their current remediations. Unknown types SHALL be ignored. When several matching scopes exist, `ban` SHALL win over `captcha`.

#### Scenario: Range captcha and Country ban
- **WHEN** the client IP is inside a Range captcha and a mapped Country ban also matches
- **THEN** the request is banned, not captcha

### Requirement: Stream Range membership hydrates from the shared blob
Each stream or alone connection SHALL rebuild in-process Range membership from `range-index` at stream start and on the stream ticker. A ticker that skips LAPI SHALL still hydrate when the blob changed. Rebuild SHALL use separate ban and captcha CIDR sets so a longer captcha prefix cannot hide a containing ban. Client IP SHALL remain the address already produced by `pkg/ip.GetRemoteIP`.

#### Scenario: First request after stream start uses existing blob
- **WHEN** `range-index` already contains a Range ban `10.0.0.0/8` and a new stream connection starts
- **THEN** a request from `10.1.2.3` is forbidden without waiting for the next stream tick

#### Scenario: Ban wins over a longer captcha prefix
- **WHEN** stream has a Range ban `10.0.0.0/8` and a Range captcha `10.1.0.0/16` and the client IP is `10.1.2.3`
- **THEN** the request is forbidden, not captcha

### Requirement: Remediation cache values may carry origin
An Ip or header-scope cache value SHALL still start with the ban/captcha/none letter (`t` / `c` / `f`). It MAY append a unit-separator and the metrics origin. `IsActiveRemediation`, `PreferRemediation`, Range index parsing, and request lookup SHALL use that letter. Lookup keys (client IP, `scope:value`, `range-index`) MUST NOT change. A value that is only the letter (today’s Redis) SHALL keep matching.

#### Scenario: Suffixed ban still remediates
- **WHEN** cache holds `t` plus a unit-separator and `crowdsec` for the client IP
- **THEN** the request is banned

#### Scenario: Bare letter still remediates
- **WHEN** cache holds only `t` for the client IP
- **THEN** the request is banned
