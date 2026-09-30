## MODIFIED Requirements

### Requirement: DecisionStore owns the origin intern table
A DecisionStore SHALL own two `pkg/intern.Table` values (each `names []string` index-is-id, `byName` string→`uint16`; empty name is id 0; lock-free `Name` for a known id): one for folded usage-metrics origins (`MetricsOrigin`, including `lists:<name>`), and one for the raw LAPI scenario. `intern.Table.ID` SHALL stay overflow at `uint16` max 65535. CrowdSec `Pack`/`Unpack`/`KindOriginString` SHALL live in `pkg/decisionstore`. The memory pack word SHALL be a `uint32` laid out as 2-bit kind, 12-bit origin id, 2-bit family, 16-bit scenario id (`kind` 0=empty / 1=`t` / 2=`c` / 3=`f`; `familyCode` 1=`ipv4`, 2=`ipv6`, 0=empty). Unpack of a packed word SHALL return ASCII `t` / `c` / `f` (or empty when kind is 0), an empty origin name, and the packed origin id. Unpack origin id MUST NOT be `uint16(word>>8)`. When the origin intern id is greater than 4095, memory pack SHALL Warn `decisionstore:intern overflow` and SHALL pack origin id `0`. Memory Put SHALL classify family with `FamilyOfHostOrCIDR` on the decision value once. The tables MUST NOT be package variables. Two DecisionStores with different reclaim keys MUST NOT share either table. Intern MUST stay off `lapi.Client` except thin forwards tests need. When origin intern would overflow `uint16`, the store SHALL log at Warn `decisionstore:intern overflow` and SHALL store a packed word with origin id `0` on memory, and SHALL store `KindOriginString(kind, origin)` on Redis without a leftover U+001F string. Redis slots SHALL be `KindOriginString` (kind, then newline, then origin; bare kind when origin is empty). Memory Ip and header writes SHALL Pack into the word map. Range-index blobs SHALL use `KindOriginString`, never a packed intern id in the blob. `HeaderScopeKey` and `IPCacheKey` SHALL live in `pkg/decisionstore`. `LiveSlot` SHALL remain `Word uint32` plus `ExpiresAt int32` (8 bytes). `LookupRemediation` SHALL still return kind, origin name, and origin id; it MUST NOT grow a scenario id. `ActiveCounts` SHALL still group origin id × family from the packed word (extractors SHALL follow this layout) and MUST NOT group by scenario.

#### Scenario: Memory stream IP write packs the intern id
- **WHEN** stream/alone memory stores an Ip ban whose origin is `crowdsec`
- **THEN** unpack of the published word returns kind `t` and OriginName of that origin id is `crowdsec`

#### Scenario: Distinct stores do not share intern ids
- **WHEN** two DecisionStores have different reclaim keys and both intern `crowdsec`
- **THEN** each store’s `OriginName` answers only from its own table

#### Scenario: Overflow stores origin id 0
- **WHEN** intern would assign an id past `uint16` max and the store Puts that Ip slot
- **THEN** memory packs the ban or captcha kind with origin id `0`
- **AND** lookup returns the kind without an origin name
- **AND** a Warn is logged
- **AND** Redis does not store a leftover U+001F string for that overflow

#### Scenario: Origin pack saturates at 12 bits
- **WHEN** origin intern assigns an id greater than 4095 and memory Puts that Ip slot
- **THEN** the packed origin id is `0`
- **AND** a Warn `decisionstore:intern overflow` is logged
- **AND** kind, family, and TTL stay on the slot

#### Scenario: ActiveCounts ignores packed scenario id
- **WHEN** a memory store Puts one Ip ban with a non-empty scenario during a tick
- **AND** PublishTick runs
- **THEN** `ActiveCounts` keys that slot by origin id and family only

## ADDED Requirements

### Requirement: DecisionStore interns the raw LAPI scenario
A DecisionStore SHALL intern the raw LAPI `scenario` on a second `pkg/intern.Table` (Scenario intern). `NewMemory` and `NewRedis` SHALL each construct that table. Store `Decision` SHALL carry a `Scenario` string field; empty is intern id 0. Stream Ip/header Put SHALL copy LAPI `item.Scenario` onto that field and SHALL keep `Origin` as `MetricsOrigin`. Live memo Put SHALL copy the raw scenario from the live pick. Lists SHALL intern twice: origin table `lists:<name>` and scenario table the raw list name. Memory pack SHALL intern `Decision.Scenario` into the 16-bit scenario field. When scenario intern would overflow `uint16`, the store SHALL log at Warn `decisionstore:scenario intern overflow` and SHALL pack scenario id `0`; kind, family, origin id, and TTL SHALL stay. Redis Put and Range upserts MUST NOT write a packed scenario id; they SHALL stay `KindOriginString(kind, folded origin)`. The metrics reporter MUST NOT own a scenario intern table.

#### Scenario: Lists intern twice
- **WHEN** stream/alone memory stores an Ip ban whose origin is `lists` and scenario is `firehol_level1`
- **THEN** OriginName of the packed origin id is `lists:firehol_level1`
- **AND** the scenario intern name for the packed scenario id is `firehol_level1`

#### Scenario: Scenario overflow keeps the decision
- **WHEN** scenario intern would assign an id past `uint16` max and the store Puts that Ip slot
- **THEN** memory packs the ban or captcha kind with scenario id `0`
- **AND** lookup still returns that kind
- **AND** a Warn `decisionstore:scenario intern overflow` is logged

#### Scenario: Redis payload has no intern id
- **WHEN** a Redis store Puts an Ip ban with a non-empty scenario
- **THEN** the Redis SET value is `KindOriginString` of kind and folded origin
- **AND** that value does not contain a packed intern id
