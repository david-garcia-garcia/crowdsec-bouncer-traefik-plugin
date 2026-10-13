## ADDED Requirements

### Requirement: DecisionStore owns the active-decision group-by
A DecisionStore SHALL keep a compact `{originID uint16, family} → int64` count of stream/alone Ip and header-scope slots. `Open`, `NewMemory`, and `NewRedis` SHALL set `countActive` true only when `crowdsecMode` is stream or alone. `countActive` MUST NOT be part of the reclaim StoreKey. When `countActive` is false, PutMany, DeleteMany, and memory PublishTick MUST NOT increment or decrement, and `ActiveCounts` SHALL return an empty snapshot. Live/none memo Put MUST NOT increment. Range MUST NOT be counted: `ApplyRangeBatch` MUST NOT adjust the map; the store MUST NOT Peek membership or query Range Helper Contains for metrics. PutMany and DeleteMany SHALL adjust the compact map (memory: while holding the same mutex as putSlot / deleteTickLocked; Redis: MGET the previous canonical `KindOriginString`, intern the origin name in-process via the store intern table, then adjust). Overwrite of an existing canonical slot SHALL decrement the previous group then increment the new. A prior-spelling extra DEL MUST NOT be a second gauge event. Memory PublishTick expiry of a counted slot SHALL decrement. Redis PublishTick SHALL remain a no-op; Redis TTL expiry without DeleteMany MUST NOT decrement. `ActiveCounts` SHALL return a snapshot copy of the compact map and MUST NOT expose `usageMetricKey` or LAPI item JSON. Family SHALL be `FamilyOfHostOrCIDR` on the decision value (header-scope Country/AS POST empty `ip_type`). Intern overflow SHALL count origin id `0`. Dispatch MUST NOT add a Go engine interface for this gauge.

#### Scenario: Stream Ip Put increments the compact map
- **WHEN** a stream/alone store Puts one Ip ban whose value is `1.2.3.4` and origin is `crowdsec`
- **THEN** `ActiveCounts` includes 1 for that origin id and `ipv4`

#### Scenario: Stream Ip Delete decrements
- **WHEN** that same store later Deletes that Ip slot
- **THEN** `ActiveCounts` omits that group (or the count is 0)

#### Scenario: Live Put does not increment
- **WHEN** a live/none store Puts a memo Ip ban
- **THEN** `ActiveCounts` is empty

#### Scenario: Range apply does not increment
- **WHEN** stream ApplyRangeBatch upserts a Range CIDR
- **THEN** `ActiveCounts` does not include that CIDR

#### Scenario: Memory PublishTick expiry decrements
- **WHEN** a stream/alone memory store holds an Ip slot whose elapsed expiry is due
- **AND** PublishTick runs with non-zero elapsed `now`
- **THEN** `ActiveCounts` no longer includes that slot

#### Scenario: Redis overwrite uses previous origin
- **WHEN** a stream/alone Redis store Puts an Ip slot that already holds a different origin
- **THEN** `ActiveCounts` decrements the previous origin group and increments the new

#### Scenario: Overflow counts origin id 0
- **WHEN** intern would overflow and a stream/alone store Puts an Ip slot
- **THEN** `ActiveCounts` keys that slot with origin id `0`
