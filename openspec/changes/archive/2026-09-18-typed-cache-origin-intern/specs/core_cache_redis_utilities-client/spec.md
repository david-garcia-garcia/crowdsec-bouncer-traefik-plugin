## ADDED Requirements

### Requirement: Redis Int uses existing byte Set and Get
`SetInt`/`GetInt` on a Redis cache Client SHALL encode the `uint32` as decimal ASCII through existing SimpleRedis `Set`/`Get` `[]byte`. Callers MUST treat that encoding as opaque. The cache MUST NOT add an Int helper on SimpleRedis. A GetInt that cannot parse that encoding (including a leftover remediation string) SHALL return `CacheMiss`. Stream and alone Redis writers MAY keep leftover strings via `Set`. Commands SHALL pass a `context.Context` (`context.Background()` when the cache API has no request context).

#### Scenario: Redis GetInt misses a leftover string
- **WHEN** a Redis cache Client Sets a leftover remediation string on an Ip key
- **THEN** GetInt of that key returns `CacheMiss`
- **AND** Get of that key returns the leftover string

#### Scenario: Redis SetInt round-trips a word
- **WHEN** a Redis cache Client SetInts key `k` to `uint32` `116`
- **THEN** GetInt of `k` returns `116`
