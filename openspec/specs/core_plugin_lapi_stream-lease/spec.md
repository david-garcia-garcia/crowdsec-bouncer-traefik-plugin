## Purpose

Guards CrowdSec stream polling so that when `updateIntervalSeconds` is 1 (the minimum allowed), the shared lease key is still stored long enough that later ticks in that second skip LAPI.

## Requirements

### Requirement: Stream poll lease TTL is at least one second
When the stream poller finds no lease in cache, it SHALL store cache key `updated` with a TTL of at least one second. That floor SHALL apply when `updateIntervalSeconds` is 1. After that store, a later poller that still sees the key MUST NOT call CrowdSec `GET /v1/decisions/stream`.

#### Scenario: Interval one stores the lease
- **WHEN** `updateIntervalSeconds` is 1 and cache key `updated` is absent
- **THEN** the stream poller stores `updated` and one LAPI stream GET occurs

#### Scenario: Stored interval-one lease skips LAPI
- **WHEN** that same client polls again while `updated` is still present
- **THEN** no further LAPI stream GET occurs
