## ADDED Requirements

### Requirement: TTL zero is a no-op on all backends
When `Client.Set` is called with `duration <= 0`, the cache SHALL NOT store the key on memory or Redis and SHALL return `nil`.

#### Scenario: Zero duration on memory
- **WHEN** a memory client calls `Set(key, value, 0)`
- **THEN** a following `Get(key)` is a miss

#### Scenario: Zero duration on Redis
- **WHEN** a Redis client calls `Set(key, value, 0)`
- **THEN** no SET is sent to Redis and a following `Get(key)` is a miss

### Requirement: Set and Delete surface write errors
`Client.Set` and `Client.Delete` SHALL return `error`. On Redis, write failures from `pkg/simpleredis` SHALL propagate to the caller. On memory, writes SHALL return `nil`.

#### Scenario: Redis Set failure
- **WHEN** the Redis writer returns an error on SET
- **THEN** `Client.Set` returns that error

#### Scenario: Redis Delete failure
- **WHEN** the Redis writer returns an error on DEL
- **THEN** `Client.Delete` returns that error

### Requirement: Read-your-writes after Redis Set
After a successful Redis `Set` on this cache Client instance, `Get` and `GetMany` for that logical key SHALL read from the writer connection until `Delete` removes the key, even when read hosts are configured.

#### Scenario: Lagging replica after Set
- **WHEN** a Redis client writes a key on the writer and the read host store does not yet hold the key
- **THEN** `Get` on that key returns the written value

### Requirement: Redis CRUD is tested in pkg/cache
`pkg/cache` tests SHALL cover Redis-backend Get/Set/Delete/GetMany including prefixed keys, miss and unreachable mapping, empty value as miss, TTL zero, write errors, and read-your-writes with a lagging read host.

#### Scenario: CI exercises redisCache
- **WHEN** `go test ./pkg/cache` runs
- **THEN** tests construct `redisCache` via fake Redis servers, not only `localCache`
