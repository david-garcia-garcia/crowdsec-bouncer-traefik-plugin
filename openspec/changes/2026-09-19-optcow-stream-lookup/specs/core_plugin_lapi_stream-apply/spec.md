## ADDED Requirements

### Requirement: Stream Ip and header apply uses the DecisionStore stream store
When the stream poller applies non-Range stream or alone Ip and header-scoped decisions, it SHALL use the DecisionStore stream store only. It SHALL call BeginTick before applying deletions and additions for that payload, apply every `deleted` entry with Delete before every `new` entry with Put for the same value, then call PublishTick once after the full payload is applied. Range CIDR collection, `ApplyRangeBatch`, and `hydrateRangeMembership` cadence SHALL stay unchanged. The poller MUST NOT keep a Client-held tick scratch map and MUST NOT branch between a live tick map and direct `cache.Client.Set` for Ip or header keys.

#### Scenario: Deleted before new in the tick clone
- **WHEN** one stream payload deletes an Ip ban and adds a replacement for the same value on memory
- **THEN** after PublishTick the stream store remediates that address with the new decision

#### Scenario: Delete-only clears the stream store slot
- **WHEN** one stream payload deletes an Ip ban and contains no replacement
- **THEN** after PublishTick that Ip key is absent from the stream store

#### Scenario: Redis apply does not require tick publish side effects
- **WHEN** Redis backs the DecisionStore and a stream payload stores an Ip ban
- **THEN** the cache Client holds the remediation without a memory-style map publish

#### Scenario: Range apply stays on cache Client
- **WHEN** a stream payload carries Range upserts and removals
- **THEN** Range still uses one read and one write on `range-index` via `ApplyRangeBatch`
- **AND** Ip and header keys are not written through Range batch
