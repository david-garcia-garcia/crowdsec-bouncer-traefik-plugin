## Purpose

Session-scoped DecisionStore intern table so stream/alone memory remediations store a packed kind-plus-origin-id instead of a per-decision origin string.

## Requirements

### Requirement: DecisionStore owns an append-only origin dictionary
A DecisionStore SHALL own one append-only dictionary that maps a first-seen `MetricsOrigin` string to the next `uint16` id and the reverse. The table MUST NOT be a package `var` and MUST NOT be shared across DecisionStore incarnations. Two `lapi.Client`s that reclaim the same store SHALL intern and resolve through that same table. Empty origin SHALL NOT consume an id. When the next id would exceed `uint16` maximum, the store MUST NOT intern that name, MUST NOT wrap ids, and SHALL log that overflow once per store. Packed ids are cache payload: a Client MUST NOT keep a second intern table for the same store.

#### Scenario: First-seen origin gets the next id
- **WHEN** stream/alone memory applies a decision whose `MetricsOrigin` is `crowdsec` and the store table is empty
- **THEN** that name interned as id 1
- **AND** a later decision with the same origin reuses id 1

#### Scenario: Shared store shares ids
- **WHEN** two stream Clients reclaim the same DecisionStore
- **AND** the first interns `lists:firehol_level1`
- **THEN** the second resolves that same id to `lists:firehol_level1`

#### Scenario: Isolated stores do not share ids
- **WHEN** two DecisionStores intern `crowdsec` independently
- **THEN** each table is private to its store

#### Scenario: Overflow stays on the string path
- **WHEN** the store already holds 65535 interned names and a new distinct `MetricsOrigin` arrives
- **THEN** that decision is stored with the existing letter plus U+001F plus origin string
- **AND** the overflow is logged once for that store
- **AND** no id wraps to 0 or 1

### Requirement: Stream/alone memory stores packed kind plus origin id
On the stream/alone memory backend, an interned Ip or header-scope remediation SHALL be stored as one packed word: the kind letter (`t` / `c` / `f` / `d`) in the low bits and the origin id in the remaining bits. The ttl_map value MUST NOT hold a per-decision origin string when the name interned. Redis SHALL still persist `RemediationWithOrigin` (letter, optional U+001F plus origin). Live and none MUST keep the string codec. Kind extraction SHALL shift/mask the packed word, or take the first letter of a leftover string, and MUST NOT take the intern write lock and MUST NOT format a U+001F string on the allow path. Origin name resolve (`table[id]` or the leftover suffix) SHALL run only when reporting a drop or building usage-metrics.

#### Scenario: Packed memory ban remediates
- **WHEN** stream memory stores an Ip ban whose origin interned
- **THEN** the ttl_map value for that IP is a packed word, not a U+001F concat
- **AND** a request from that IP is banned

#### Scenario: Allow path does not resolve origin
- **WHEN** a packed memory hit is an allow (none / miss after prefer)
- **THEN** the intern table is not consulted for a name
- **AND** no U+001F string is formatted from that word

#### Scenario: Redis still writes the origin string
- **WHEN** Redis is enabled and stream applies an Ip ban with origin `crowdsec`
- **THEN** the Redis value is the letter plus U+001F plus `crowdsec`

### Requirement: Memory Range values pack the same way
On the stream/alone memory path, Range upserts SHALL intern and pack before `ApplyRangeBatch`. In-process Range membership SHALL hold those packed (or leftover string) values per CIDR. Redis MAY still persist the full suffix on `range-index`. Letter-only Range lines SHALL stay valid.

#### Scenario: Memory Range membership does not keep unique concats
- **WHEN** stream memory upserts a Range ban whose origin interned
- **THEN** membership for that CIDR holds the packed value, not a per-CIDR U+001F concat
- **AND** a client IP inside that CIDR is banned
