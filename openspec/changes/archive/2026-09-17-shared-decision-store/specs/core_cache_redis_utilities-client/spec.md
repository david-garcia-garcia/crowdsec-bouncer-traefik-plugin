## ADDED Requirements

### Requirement: Cache Client exposes a narrow lease acquire
`cache.Client` SHALL expose one acquire that talks to the writer plus prefix (Redis) or the memory mutex (local). Redis acquire SHALL call vendored SimpleRedis `Eval` (`EVALSHA` then `EVAL` on NOSCRIPT) with the prefixed key. Memory acquire SHALL lock around miss+Set. The method MUST NOT contain stream poller or LAPI query logic. The cache MUST NOT add a SetNX wrapper; SimpleRedis `Set` remains SET EX only. Acquire SHALL pass a `context.Context` (`context.Background()` when the cache API has no request context).

#### Scenario: Redis acquire uses Eval not Get-then-Set
- **WHEN** a Redis cache Client acquires an absent lease key
- **THEN** the writer sends `EVALSHA` or `EVAL`
- **AND** it does not send a GET followed by a SET for that acquire

#### Scenario: Memory acquire serializes miss and Set
- **WHEN** two goroutines acquire the same absent memory lease key
- **THEN** exactly one acquire wins
- **AND** the loser sees the key present
