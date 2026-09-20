## Purpose

Writes one CrowdSec stream payload into the DecisionStore so a same-window replacement (new ban plus deleted prior for the same IP or CIDR) stays active.

## Requirements

### Requirement: Stream apply writes deleted before new
When the stream poller applies one CrowdSec `/v1/decisions/stream` payload, it SHALL apply every `deleted` decision before every `new` decision through `pkg/decisionstore.Store`. It SHALL call BeginTick before applying deletions and additions for that payload, apply every non-Range `deleted` entry with DeleteMany (flushing each `PutManyChunk`) before every non-Range `new` entry with PutMany (flushing each `PutManyChunk`) for the same value, then call PublishTick once after the full payload is applied. Range CIDRs SHALL be removed from the shared `range-index` blob before a replacement for that same CIDR is upserted, via one `ApplyRangeBatch` (one read, removals then upserts, one write). After apply, Range membership SHALL be rebuilt from that blob (`HydrateRange`). The poller MUST NOT keep a Client-held tick scratch map, MUST NOT branch between a live tick map and `cache.Client.Set`, and MUST NOT treat a stream lease (`updated` / `Acquire`) as this apply order. Intra-instance poll lock is owned by `core_plugin_lapi_stream-single-flight`. A Range apply that could not read the index SHALL be a failed poll so stream startup stays set and the retry asks for the full decision set.

#### Scenario: Same-window IP replacement stays banned
- **WHEN** one stream payload contains a new Ip ban for `203.0.113.10` and a deleted prior for that same value
- **THEN** the Store still remediates `203.0.113.10` after PublishTick

#### Scenario: Same-window Range replacement stays banned
- **WHEN** one stream payload contains a new Range ban for `10.0.0.0/8` and a deleted prior for that same CIDR
- **THEN** a client IP inside `10.0.0.0/8` is still remediating after apply

#### Scenario: Delete-only still clears
- **WHEN** one stream payload deletes an Ip ban and contains no replacement for that value
- **THEN** that IP slot is absent after PublishTick

#### Scenario: Redis apply does not require a memory map publish
- **WHEN** Redis backs the Store and a stream payload stores an Ip ban
- **THEN** Redis holds `KindOriginString` for that Ip key without a memory-style map publish

#### Scenario: Range apply stays on ApplyRangeBatch
- **WHEN** a stream payload carries Range upserts and removals
- **THEN** Range uses one read and one write on `range-index` via `ApplyRangeBatch`
- **AND** Ip and header keys are not written through Range batch

#### Scenario: Failed range apply keeps startup
- **WHEN** a stream poll’s Range apply could not read the index
- **THEN** the poll reports the failure
- **AND** stream startup stays set so the next query asks for the full set
