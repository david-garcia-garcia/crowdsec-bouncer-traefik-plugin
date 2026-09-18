## ADDED Requirements

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
