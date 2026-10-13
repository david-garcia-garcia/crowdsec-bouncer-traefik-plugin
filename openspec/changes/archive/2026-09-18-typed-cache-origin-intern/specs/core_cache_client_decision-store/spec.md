## MODIFIED Requirements

### Requirement: Cache payloads stay opaque strings
A cache Client SHALL store and return opaque strings on `Set`/`Get`/`GetMany` and SHALL also store and return a machine word on `SetInt`/`GetInt` (`uint32` is enough). The cache package MUST NOT export CrowdSec remediation names (`BannedValue`, `CaptchaValue`, `NoBannedValue`). The cache package MUST NOT know kind, origin, Packed, Stored, Leftover, Remediation, or range-index separators. It MUST NOT export `SetRemediation`, `GetManyStored`, `ParsePackedOriginID`, or a `MemoryBackend` type switch for remediations. Store errors SHALL remain `CacheMiss` and `CacheUnreachable`. `GetInt` SHALL return `CacheMiss` when the key is absent or the stored value is not that word (including a leftover string). Client address, when this leaf mentions it, SHALL reuse `pkg/ip.GetRemoteIP` (do not parse `RemoteAddr`).

#### Scenario: Cache tests treat values as opaque
- **WHEN** a cache test Sets and Gets a payload
- **THEN** it uses a string literal, not a decisionscope or captcha const

#### Scenario: SetInt then GetInt returns the word
- **WHEN** a memory cache Client SetInts key `k` to `uint32` `0x00637374`
- **THEN** GetInt of `k` returns that same word

#### Scenario: GetInt misses a leftover string
- **WHEN** a memory cache Client Sets key `k` to a leftover string
- **THEN** GetInt of `k` returns `CacheMiss`
- **AND** Get of `k` returns that string

## ADDED Requirements

### Requirement: DecisionStore owns the origin intern table
A DecisionStore SHALL own an append-only origin intern table (name→`uint16`) and a lock-free `OriginName` lookup. The pack word SHALL be `uint32(kind[0]) | uint32(id)<<8`. The table MUST NOT be a package variable. Two DecisionStores with different reclaim keys MUST NOT share the table. Intern MUST stay off `lapi.Client` except thin forwards tests need. When intern would overflow `uint16`, that origin SHALL stay on the leftover string path. Stream and alone memory Ip and header writes SHALL pack and `SetInt` when intern succeeds. Redis, live/none, and overflow SHALL keep leftover strings via `Set`. Range-index blobs SHALL use `Set`, never `SetInt`. Client address SHALL reuse `pkg/ip.GetRemoteIP`. CrowdSec cursor identity SHALL reuse `SessionHex`.

#### Scenario: Memory stream IP write packs the intern id
- **WHEN** stream/alone memory stores an Ip ban whose origin is `crowdsec`
- **THEN** GetInt of that Ip key returns a word whose low byte is `t` and whose origin id names `crowdsec` via `OriginName`

#### Scenario: Distinct stores do not share intern ids
- **WHEN** two DecisionStores have different reclaim keys and both intern `crowdsec`
- **THEN** each store’s `OriginName` answers only from its own table

#### Scenario: Overflow keeps leftover strings
- **WHEN** intern would assign an id past `uint16` max
- **THEN** that origin’s Ip slot is stored with `Set` as a leftover string
- **AND** GetInt of that slot is `CacheMiss`
