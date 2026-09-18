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

### Requirement: Stream lease acquire is atomic
When the stream poller needs the `updated` lease, it SHALL acquire it in one DecisionStore operation. Redis SHALL use one vendored SimpleRedis `Eval` (`EVALSHA` then `EVAL` on NOSCRIPT) that sets the key only when absent. Memory SHALL take a mutex around miss+Set of `updated` (vendored `ttl_map` Get and Set are separately locked; there is no compare-and-swap). The poller MUST NOT Get-then-Set. Two concurrent acquirers on one store MUST yield exactly one winner that may call CrowdSec `GET /v1/decisions/stream`. The loser MUST treat the lease as present and MUST NOT call that GET. Implementations MUST NOT use `atomic.Pointer[T]`. Write-once Client scalars MUST NOT become mutable to hold the lease.

#### Scenario: Two memory pollers one fetch
- **WHEN** two stream pollers share one memory DecisionStore and `updated` is absent
- **THEN** exactly one LAPI stream GET occurs
- **AND** the other poller skips LAPI

#### Scenario: Two Redis pollers one fetch
- **WHEN** two stream pollers share one Redis DecisionStore and `updated` is absent
- **THEN** exactly one LAPI stream GET occurs
- **AND** the other poller skips LAPI

### Requirement: A failed poll releases the stream lease
When the stream poller wins the `updated` lease and the poll then fails at any stage — the CrowdSec stream GET, decoding the response, or applying the decisions — it SHALL release that lease before returning the error, by deleting the `updated` key from the DecisionStore. Release SHALL behave the same on the Redis and the in-memory store. The next tick, on this instance or another, SHALL therefore be able to acquire the lease immediately instead of waiting out `max(updateIntervalSeconds - 1, 1)` seconds. The lease TTL, the single-operation `Acquire`, and the loser branch MUST NOT change. A poll that succeeds MUST keep the lease so later ticks in the same interval still skip LAPI.

#### Scenario: Failed stream GET frees the lease
- **WHEN** the poller wins the `updated` lease and the CrowdSec stream GET fails
- **THEN** the poller returns the error
- **AND** the `updated` key is absent from the DecisionStore

#### Scenario: The next tick re-polls immediately
- **WHEN** a poll failed and released the lease
- **THEN** the next poll acquires the lease and calls CrowdSec `GET /v1/decisions/stream`

#### Scenario: Successful poll keeps the lease
- **WHEN** a poll succeeds
- **THEN** the `updated` key is still present and a later poll in the same interval skips LAPI
