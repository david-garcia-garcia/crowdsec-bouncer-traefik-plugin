## Purpose

Writes one CrowdSec stream payload into the DecisionStore so a same-window replacement (new ban plus deleted prior for the same IP or CIDR) stays active.

## Requirements

### Requirement: Stream apply writes deleted before new
When the stream poller applies one CrowdSec `/v1/decisions/stream` payload, it SHALL apply every `deleted` decision before every `new` decision. Ip and header-mapped scopes SHALL delete the stored slot before a replacement for that same value is stored. Range CIDRs SHALL be removed from the shared `range-index` blob before a replacement for that same CIDR is upserted. The Range index write SHALL stay one cache read and one cache write. After apply, Range membership SHALL be rebuilt from that blob. The stream lease (`updated` / `Acquire`) and the intra-instance poll lock MUST NOT be treated as this apply order.

#### Scenario: Same-window IP replacement stays banned
- **WHEN** one stream payload contains a new Ip ban for `203.0.113.10` and a deleted prior for that same value
- **THEN** the DecisionStore still remediates `203.0.113.10` after apply

#### Scenario: Same-window Range replacement stays banned
- **WHEN** one stream payload contains a new Range ban for `10.0.0.0/8` and a deleted prior for that same CIDR
- **THEN** a client IP inside `10.0.0.0/8` is still remediating after apply

#### Scenario: Delete-only still clears
- **WHEN** one stream payload deletes an Ip ban and contains no replacement for that value
- **THEN** that IP slot is absent after apply
