## ADDED Requirements

### Requirement: Store lookup returns the winning decision's time left
`Store.LookupRemediation` SHALL return the time left on the decision the merge chose, on the engine's clock at lookup: memory from `LiveSlot.DecisionEnd` (elapsed clock), Redis from the 4th line of the slot value (wall-clock Unix seconds). Zero SHALL mean unknown: no end stored, an end that is not a positive integer or already past, or a Range winner. `Decision.DecisionDurationSec` SHALL carry the decision's remaining duration apart from `DurationSec` (the store TTL).

#### Scenario: Stream apply sets both durations
- **WHEN** stream apply stores a non-Range decision with a parsed duration of 3600 seconds
- **THEN** the stored `Decision` has `DurationSec` 3600 and `DecisionDurationSec` 3600

#### Scenario: Negative live memo carries no end
- **WHEN** live mode memoizes a clean (`f`) result for a client address
- **THEN** that slot has no decision end

#### Scenario: Memory stream hit returns the time left
- **WHEN** stream apply stores an Ip ban with duration 3600 seconds on a memory store and PublishTick runs
- **THEN** `LookupRemediation` for that address returns kind ban and a time left greater than 0 and at most 3600 seconds

#### Scenario: Live memo keeps the decision end past the cache TTL
- **WHEN** live mode memoizes an Ip ban with store TTL 60 seconds and decision duration 14400 seconds
- **THEN** a lookup while the memo lives returns a time left greater than 60 seconds
- **AND** the memo still expires after 60 seconds

#### Scenario: Redis writes the end as the fourth line
- **WHEN** a Redis store Puts an Ip ban with origin `crowdsec`, scenario `crowdsecurity/http-probing`, and decision duration 3600 seconds
- **THEN** the Redis SET value is `t`, `crowdsec`, `crowdsecurity/http-probing`, and a Unix second about 3600 seconds after now, separated by newlines

#### Scenario: Redis end with empty origin and scenario
- **WHEN** a Redis store Puts an Ip ban with empty origin, empty scenario, and decision duration 600 seconds
- **THEN** the Redis SET value is `t`, two empty lines, and the end line
- **AND** lookup returns kind ban, empty origin, and a time left greater than 0

#### Scenario: Redis value without an end
- **WHEN** Redis holds `t`, newline, `crowdsec`, newline, `ssh-bf` for the client address
- **THEN** lookup returns kind ban, origin `crowdsec`, and time left zero

#### Scenario: Redis end that is not a positive integer
- **WHEN** Redis holds `t`, `crowdsec`, `ssh-bf`, and `soon` on four lines for the client address
- **THEN** lookup returns kind ban, origin `crowdsec`, and time left zero

#### Scenario: Redis end already passed on this replica's clock
- **WHEN** Redis holds a ban whose 4th line is a Unix second before this replica's now
- **THEN** lookup returns kind ban and time left zero

#### Scenario: A three-line reader still reads kind and origin
- **WHEN** a value with an end is split into at most three lines (kind, origin, rest), as fork versions from v1.9.4 read it
- **THEN** the first line is the kind and the second line is the origin

#### Scenario: Range winner has no end
- **WHEN** a stream store holds an Ip captcha with an end for the client address and Range membership bans that address
- **THEN** lookup returns kind ban and time left zero

#### Scenario: Header-scope ban over an Ip captcha returns the header decision's end
- **WHEN** the store holds an Ip captcha with 600 seconds left and a Country ban with 3600 seconds left that the request's mapped header matches
- **THEN** lookup returns kind ban and a time left greater than 600 seconds

## MODIFIED Requirements

### Requirement: DecisionStore owns the origin intern table
The memory engine SHALL own two `pkg/intern.Table` values (each `names []string` index-is-id, `byName` string→`uint16`; empty name is id 0; lock-free `Name` for a known id): one for folded usage-metrics origins (`MetricsOrigin`, including `lists:<name>`), and one for the raw LAPI scenario. `intern.Table.ID` SHALL stay overflow at `uint16` max 65535. CrowdSec `packWord`/`unpackWord`/`KindOriginString` SHALL live in `pkg/decisionstore`. The memory pack word SHALL be a `uint32` laid out as 2-bit kind, 12-bit origin id, 2-bit family, 16-bit scenario id (`kind` 0=empty / 1=`t` / 2=`c` / 3=`f`; `familyCode` 1=`ipv4`, 2=`ipv6`, 0=empty). `unpackWord` SHALL return the kind letter (`t` / `c` / `f`, or empty when kind is 0), the origin id, the family, and the scenario id. Unpack origin id MUST NOT be `uint16(word>>8)`. When the origin intern id is greater than 4095, memory pack SHALL pack origin id `0` and SHALL NOT log. Memory Put SHALL classify family with `FamilyOfHostOrCIDR` on the decision value once. The tables MUST NOT be package variables. Two DecisionStores with different reclaim keys MUST NOT share either table. Intern MUST stay off `lapi.Client` except thin forwards tests need. When origin intern would overflow `uint16`, the store SHALL store a packed word with origin id `0` on memory and SHALL NOT log, and SHALL store the Redis slot value for that kind and origin without a leftover U+001F string. Redis slots SHALL be newline-separated lines: kind, origin, raw scenario, then the decision end in wall-clock Unix seconds. Trailing lines that are not set SHALL be omitted (bare kind when origin, scenario, and end are all empty); a line before a set line SHALL be written empty. Readers SHALL take kind and origin from the first two lines. Memory Ip and header writes SHALL Pack into the word map. Range-index blobs SHALL use `KindOriginString`, never a packed intern id in the blob. `HeaderScopeKey` and `IPCacheKey` SHALL live in `pkg/decisionstore`. `LiveSlot` SHALL be `Word uint32`, `ExpiresAt int32`, and `DecisionEnd int32` (12 bytes). `LookupRemediation` SHALL return kind, origin name, origin id, and the winning decision's time left; it MUST NOT grow a scenario id. `ActiveCounts` SHALL still group origin id × family from the packed word (extractors SHALL follow this layout) and MUST NOT group by scenario.

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
- **AND** no Warn is logged
- **AND** Redis does not store a leftover U+001F string for that overflow

#### Scenario: Origin pack saturates at 12 bits
- **WHEN** origin intern assigns an id greater than 4095 and memory Puts that Ip slot
- **THEN** the packed origin id is `0`
- **AND** no Warn is logged
- **AND** kind, family, and TTL stay on the slot

#### Scenario: ActiveCounts ignores packed scenario id
- **WHEN** a memory store Puts one Ip ban with a non-empty scenario during a tick
- **AND** PublishTick runs
- **THEN** `ActiveCounts` keys that slot by origin id and family only

#### Scenario: LiveSlot is twelve bytes
- **WHEN** the size of `LiveSlot` is measured
- **THEN** it is 12 bytes

### Requirement: DecisionStore interns the raw LAPI scenario
The memory engine SHALL intern the raw LAPI `scenario` on a second `pkg/intern.Table` (Scenario intern). Only that engine constructs the origin and scenario tables. Redis SHALL NOT. Store `Decision` SHALL carry a `Scenario` string field; empty is intern id 0. Stream Ip/header Put SHALL copy LAPI `item.Scenario` onto that field and SHALL keep `Origin` as `MetricsOrigin`. Live memo Put SHALL copy the raw scenario from the live pick. Lists SHALL intern twice: origin table `lists:<name>` and scenario table the raw list name. Memory pack SHALL intern `Decision.Scenario` into the 16-bit scenario field. When scenario intern would overflow `uint16`, the store SHALL pack scenario id `0` and SHALL NOT log; kind, family, origin id, and TTL SHALL stay. Redis Put MUST NOT write a packed scenario id; it SHALL write the raw scenario text on the third line of the slot value (kind, folded origin, scenario, end). Range upserts MUST NOT write a packed scenario id; they SHALL stay `KindOriginString(kind, folded origin)`. The metrics reporter MUST NOT own a scenario intern table.

#### Scenario: Lists intern twice
- **WHEN** stream/alone memory stores an Ip ban whose origin is `lists` and scenario is `firehol_level1`
- **THEN** OriginName of the packed origin id is `lists:firehol_level1`
- **AND** the scenario intern name for the packed scenario id is `firehol_level1`

#### Scenario: Scenario overflow keeps the decision
- **WHEN** scenario intern would assign an id past `uint16` max and the store Puts that Ip slot
- **THEN** memory packs the ban or captcha kind with scenario id `0`
- **AND** lookup still returns that kind
- **AND** no Warn is logged

#### Scenario: Redis payload has no intern id
- **WHEN** a Redis store Puts an Ip ban with a non-empty scenario
- **THEN** the first two lines of the Redis SET value are the kind and the folded origin, and the third line is the raw scenario
- **AND** that value does not contain a packed intern id
