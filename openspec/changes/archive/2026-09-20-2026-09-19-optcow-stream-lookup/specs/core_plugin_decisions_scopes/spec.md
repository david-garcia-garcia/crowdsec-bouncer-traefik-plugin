## MODIFIED Requirements

### Requirement: Range decisions match by CIDR containment
When a decision scope is `Range` (any case), the bouncer SHALL treat `value` as a CIDR and remediate a request whose client IP is inside that network. A parseable bare IP SHALL be stored as that host `/32` (IPv4) or `/128` (IPv6) on range-index upsert and remove so write and delete pair. Membership rebuild SHALL use `ParseCIDR` only; a leftover bare-IP index line SHALL be skipped. Range membership SHALL be stored on one shared Store key `range-index` as `cidr=kind` lines, with origin on the following newline line when present, so Redis replicas that only read can still match. When several containing CIDRs hit, `ban` SHALL win over `captcha`. In stream and alone modes, the request path SHALL match Range from Store membership rebuilt from that blob and MUST NOT read `range-index` on the request. live and none SHALL keep skipping `range-index` and expand Range via LAPI `?ip=`.

#### Scenario: Stream Range contains the client
- **WHEN** stream or alone mode has a Range ban `10.0.0.0/8` and the client IP is `10.1.2.3`
- **THEN** the request is forbidden

#### Scenario: Redis replica that did not poll still matches Range
- **WHEN** Redis holds a Range ban `10.0.0.0/8` on `range-index` and this instance did not apply that stream payload
- **THEN** a request from `10.1.2.3` is forbidden after this instance hydrates from the blob

#### Scenario: Leftover bare Range line does not remediate
- **WHEN** `range-index` holds `192.0.2.1=t` and the client IP is `192.0.2.1`
- **THEN** the request is allowed

### Requirement: Range index apply does not write from an index it could not read
`RangeIndex` SHALL distinguish a miss from a failed read: a miss SHALL be an empty index with no error, and any other store failure SHALL be returned. `ApplyRangeBatch` SHALL return that error and MUST NOT write `range-index`, because the blob is shared and rebuilding it from an unread base drops every Range decision this poll did not carry. A stream poll whose Range apply failed SHALL be reported as a failed poll so stream startup stays set and the retry asks for the full decision set. There is no stream lease to release.

#### Scenario: Unreachable read preserves the shared index
- **WHEN** RangeIndex answers `store:unreachable` and a poll would upsert a new Range CIDR
- **THEN** `ApplyRangeBatch` returns the error and the stored `range-index` still holds the CIDRs it held before

#### Scenario: Store miss still applies
- **WHEN** RangeIndex is empty (`store:miss` mapped to empty) and the poll upserts `10.0.0.0/8`
- **THEN** `range-index` is written with that line

#### Scenario: A failed range apply keeps startup
- **WHEN** a stream poll’s Range apply could not read the index
- **THEN** the poll reports the failure and the connection stays in startup so the next query asks for the full set

### Requirement: Decision remediations are decisionscope codes
`pkg/decisionscope` SHALL own the ban, captcha, and none letters as `BannedValue` (`t`), `CaptchaValue` (`c`), and `NoBannedValue` (`f`). `RemediationValue` SHALL map LAPI type `ban` to `BannedValue` and `captcha` to `CaptchaValue`. `RemediationKind` SHALL return the first letter only. Callers that compare a decision remediation SHALL use those names. Persistence, pack, Range membership, and request lookup SHALL live in `pkg/decisionstore`. Wire values MUST remain `t`, `c`, and `f`.

#### Scenario: LAPI ban still stores t
- **WHEN** a decision type is `ban`
- **THEN** the stored remediation kind is `t`

### Requirement: Matching does not import Traefik config
Request lookup SHALL consult Range membership from the Store. Nil or empty membership SHALL be a Range miss. `pkg/decisionscope` MUST NOT import the Traefik plugin configuration package and MUST NOT own lookupHits. Callers MUST NOT pass a Crowdsec-mode flag; live and none leave membership empty until they hydrate (they do not).

#### Scenario: Non-empty membership remediates
- **WHEN** Range membership holds a ban that contains the client IP
- **THEN** the request is remediating from that membership

### Requirement: Remediation values carry kind then origin
An Ip, header-scope, or Range remediation SHALL start with the ban/captcha/none letter (`t` / `c` / `f`). Redis slots and Range Helper metadata SHALL use `KindOriginString` (kind, then newline, then origin; bare kind when origin is empty). Leftover U+001F, `RemediationWithOrigin`, and `RemediationOrigin` MUST NOT exist. `RemediationKind` SHALL live in `pkg/decisionscope` and SHALL return the first letter only. `range-index` stays one key whose records are `cidr=kind` plus an optional origin line. Packed intern ids SHALL NOT appear in that blob. `IsActiveRemediation`, `PreferRemediation`, and request lookup SHALL use that letter. In-process Range membership SHALL return the stored string of the winning CIDR (ban over captcha; if several bans contain the IP, the longest-prefix matching ban). Request lookup SHALL be `Store.LookupRemediation` (memory packed words; Redis `KindOriginString`). Origin name SHALL be resolved from the DecisionStore intern table only when the winning kind is remediating. The allow-path packed read MUST NOT take a second intern lock. Lookup key *shapes* (client IP, `scope:value`, `range-index`) MUST NOT change; `HeaderScopeKey` and `IPCacheKey` SHALL live in `pkg/decisionstore`. Client address SHALL reuse `pkg/ip.GetRemoteIP` / `clientRequest.remoteIP`. A value that is only the letter SHALL keep matching.

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

### Requirement: Range hit recovers stored remediation from the winning prefix
When in-process Range membership remediates a client IP, it SHALL return the utilities Helper metadata already held on the winning prefix of the matching ban or captcha set. It MUST NOT re-parse `storedByCIDR` on that request. Nil or empty membership SHALL still be a miss. Ban SHALL still win over captcha. Range metadata SHALL be `KindOriginString` (kind plus optional newline origin). The client address SHALL remain the `net.IP` already produced by `pkg/ip.GetRemoteIP`. The `range-index` blob format SHALL stay `cidr=kind` plus optional origin line. Ban and captcha MUST stay on separate Helpers. `Helper.Contains` and `Count` SHALL use the published utilities RLock (`traefik-middleware-utilities` v1.0.5). This plugin MUST NOT re-patch `vendor/.../iplookup/helper.go`.

#### Scenario: Suffixed Range hit returns the stored origin
- **WHEN** membership holds `10.0.0.0/8=t` then a newline and `crowdsec` and the client IP is `10.1.2.3`
- **THEN** remediation is that stored string

#### Scenario: Longer ban prefix wins the origin
- **WHEN** membership holds a wide ban with origin `crowdsec` and a narrower ban with origin `cscli` that both contain the client IP
- **THEN** remediation is the narrower stored string

### Requirement: Live IP cache slot is the IP query result
When live mode writes a client-address store entry after a LAPI lookup, that entry SHALL be the client-address (`?ip=`) query result only. Header-mapped remediations SHALL stay on the header-scope keys. `LiveLookup` SHALL return `(kind, origin, error)` fields and MUST NOT concat-then-split. Memo SHALL be Store Put (same Store as stream; no `liveStore` type). A clean client-address query SHALL write the none payload on the client-address key even when a header-mapped query remediates. A remediating client-address query SHALL write that client-address remediation on the client-address key. When a header-mapped query fails and the merged verdict is not active, the lookup MUST NOT write a none payload on the client-address key.

#### Scenario: Header ban does not land on the IP key
- **WHEN** live mode queries a clean client address and a mapped Country ban `FR`
- **THEN** the client-address store key holds the none payload
- **AND** the Country header-scope key holds the ban
- **AND** `LiveLookup` returns kind ban and origin from the Country decision

#### Scenario: Later header identity does not inherit the ban
- **WHEN** the previous write has happened and a later Store lookup uses the same client address with Country `DE`
- **THEN** that lookup does not remediate from the `FR` ban
