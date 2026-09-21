## ADDED Requirements

### Requirement: Client.New holds Redis readers by pointer
`Client.New` with Redis enabled SHALL allocate a distinct `*simpleredis.SimpleRedis` for the writer and for each `readHosts` entry, call `Init` on that pointer, and store those pointers on `redisCache`. It MUST NOT copy a `SimpleRedis` value into `readers` after `Init`. `nextReader` SHALL return the stored pointers (or the writer when `readHosts` is empty).

#### Scenario: New stores distinct reader pointers
- **WHEN** `Client.New` is called with Redis enabled and two read hosts
- **THEN** `redisCache` has a non-nil writer pointer, two non-nil reader pointers distinct from each other and from the writer, and `nextReader` returns those same reader pointers
