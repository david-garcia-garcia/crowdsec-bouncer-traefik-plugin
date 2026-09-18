## Purpose

What a write lifetime means at the `cache.Client` boundary: which durations are a write at all, and
what the client does with one that is not. Backend-independent, and it covers the lease verb as well
as the value verb.

## Requirements

### Requirement: A non-positive lifetime is not a write
`Client.Set` SHALL treat a `duration` of zero or less as a no-op and MUST NOT reach either backend
with it. The guard SHALL live at the `Client` boundary so both backends are covered once. A rejected
write MUST NOT disturb an entry that is already cached under that key, and MUST NOT return the
caller an error, because `Set` has no error to return and that plumbing is out of scope.

The guard exists because the two backends disagreed and one of them was dangerous. The in-memory TTL
map stored a negative lifetime as an entry that **never expires**, so a cached ban outlived the
decision that justified it with no upper bound; Redis answered the same write
`ERR invalid expire time in 'set' command`, so the value was silently not cached and every call
logged an error.

#### Scenario: A zero or negative lifetime caches nothing
- **WHEN** `Client.Set` is called with a duration of `0`, `-1`, or `-3600` on the memory backend
- **THEN** a following `Get` for that key returns `cache:miss`
- **AND** no entry that never expires is created

#### Scenario: A rejected write leaves a live entry alone
- **WHEN** a key holds a value written with a positive lifetime, and `Set` is then called for that
  key with a non-positive one
- **THEN** `Get` still returns the value written with the positive lifetime

#### Scenario: Nothing reaches Redis
- **WHEN** `Client.Set` is called with a non-positive duration on the Redis backend
- **THEN** the writer receives no `SET` command
- **AND** no error is logged for that call

### Requirement: A non-positive lifetime takes no lease
`Client.Acquire` SHALL reject a `duration` of zero or less, returning `false` and an error whose text
is `cache:bad-ttl`, before it reaches either backend. Returning "not won" is the safe reading: a
lease whose end cannot be bounded is not a lease.

In memory a negative lease duration took a lease that **never expired**, so that instance stopped
polling the stream for the life of the process, and a zero one stored nothing, so every caller won
and the lease excluded nobody. On Redis the Lua body runs the same `SET ... EX` and earned the same
rejection, which `handleStreamCache` would count as a poll failure.

#### Scenario: The lease is not taken and the key stays free
- **WHEN** `Acquire` is called with a duration of `0` or `-1`
- **THEN** it returns `false` and `cache:bad-ttl`
- **AND** a following `Acquire` for that key with a positive duration wins

#### Scenario: No Eval reaches Redis
- **WHEN** `Acquire` is called with a non-positive duration on the Redis backend
- **THEN** the writer receives no `EVAL` and no `EVALSHA`

### Requirement: Delete carries no lifetime
`Client.Delete` SHALL keep its single-argument shape. There is no duration on that verb, so there is
nothing to guard, and one MUST NOT be added to make the two verbs look alike.

#### Scenario: Delete signature
- **WHEN** a reviewer inspects `Client.Delete`
- **THEN** it takes the key only
