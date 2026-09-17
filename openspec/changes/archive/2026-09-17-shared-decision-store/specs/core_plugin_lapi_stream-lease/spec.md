## ADDED Requirements

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
