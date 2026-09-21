## ADDED Requirements

### Requirement: Get uses nextReader only
When Redis read hosts are set, Get and GetMany SHALL call `nextReader` only. A miss or replica error MUST NOT be retried on the writer. The cache MUST NOT keep a local set of recently written keys. When the reader list is empty, `nextReader` SHALL return the writer.

#### Scenario: Replica miss is not retried on the writer
- **WHEN** Redis has one or more read hosts and Get on the selected reader returns miss
- **THEN** Get returns `cache:miss`
- **AND** the writer is not called for that Get

#### Scenario: Replica unreachable is not retried on the writer
- **WHEN** Redis has one or more read hosts and Get on the selected reader is unreachable
- **THEN** Get returns `cache:unreachable`
- **AND** the writer is not called for that Get

### Requirement: Set and Delete are void
`cache.Client` Set and Delete SHALL return no error. Redis Set and Delete SHALL use the writer, log a Redis error, and return. The cache interface Set and Delete MUST NOT grow an error return. Stream and live callers MUST NOT fail closed on a write miss.

#### Scenario: Redis Set error is logged and discarded
- **WHEN** Redis Set on the writer fails
- **THEN** the error is logged
- **AND** `Client.Set` returns without an error value

### Requirement: Redis SET EX uses the duration as given
Redis Set SHALL send `SET EX` with the duration integer as given, including `0`. The cache MUST NOT omit `EX`, clamp a non-positive duration, or skip the Redis write because duration is `0`. Memory `Heap.Set` SHALL no-op when `ttl` is `0` (does not store). Redis and memory MUST NOT be aligned.

#### Scenario: Redis Set with duration 0 sends EX 0
- **WHEN** Redis `Client.Set` is called with duration `0`
- **THEN** the writer sends `SET` with `EX 0`
- **AND** the write is not skipped

#### Scenario: Memory Set with ttl 0 does not store
- **WHEN** a memory `Client.Set` is called with duration `0`
- **THEN** the key is absent on a following Get
