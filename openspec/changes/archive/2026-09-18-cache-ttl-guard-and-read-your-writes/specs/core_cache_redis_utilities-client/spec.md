## Purpose

The plugin Redis cache uses the vendored traefik-middleware-utilities SimpleRedis client, not `pkg/simpleredis` and not the published `github.com/maxlerebourg/simpleredis` module.

## ADDED Requirements

### Requirement: A key just written reads from the writer for a bounded window
`redisCache.set`, `redisCache.delete`, and `redisCache.acquire` SHALL record the key they write, and
`get` and `getMany` SHALL use the writer while **any** requested key is still inside that window.
Outside it they SHALL keep the round-robin over the read hosts. The key is recorded **before** the
write goes out, so a read taken while that write is still in flight also lands on the writer. A
client with no read hosts already reads the writer and SHALL do no pin bookkeeping.

The window SHALL be a constant in `pkg/cache`. It MUST NOT become a configuration key: the fix is a
correctness floor, not an operator preference. The guarantee is explicitly bounded — a replica
lagging longer than the window is a broken deployment, and no read routing inside the plugin can
hide that.

Reads MUST NOT all be sent to the writer. The read hosts exist to carry the per-request lookup load,
and removing that is a regression every request in every deployment pays to close a window that only
lagging-replica deployments have. The window MUST NOT be a single deadline covering every key
either: in `live` mode the cache is a per-request memo, writes never stop, and such a deadline would
never lapse, reaching writer-only reads by accident.

#### Scenario: A just-banned IP is not read back from a lagging replica
- **WHEN** a client with one read host that has not received the writer's data stores a remediation for an IP
- **AND** a `Get` or a `GetMany` for that IP follows immediately
- **THEN** the stored remediation comes back, not `cache:miss`

#### Scenario: A just-dropped decision is not read back as active
- **WHEN** both the writer and the read host hold a remediation for an IP, and the client deletes it
- **AND** a `Get` for that IP follows immediately
- **THEN** the result is `cache:miss`, not the remediation the read host still holds

#### Scenario: The read hosts carry reads again once the window elapses
- **WHEN** the window after a write has elapsed
- **THEN** a following `Get` for that key is served by a read host
- **AND** the writer serves no further `GET` for it

#### Scenario: Writing one key does not pin another
- **WHEN** one key is written and a different, untouched key is read
- **THEN** that read is served by a read host

### Requirement: The pinned-key set is capped and overflows toward the writer
The recorded-key set SHALL have a fixed cap. On reaching it the cache SHALL first drop entries whose
window has elapsed, and if it is still full SHALL pin **every** read for the window instead of
growing the set or dropping keys. A `startup=true` stream pull writes the whole decision list and is
exactly this case. Overflow MUST NOT fall back to the read hosts: the failure direction is the
writer.

#### Scenario: A burst past the cap does not grow the set
- **WHEN** more keys than the cap are written inside one window
- **THEN** the recorded-key set holds no more than the cap

#### Scenario: A burst past the cap keeps reads off the replicas
- **WHEN** more keys than the cap are written inside one window
- **AND** a key that was never written is then read
- **THEN** the writer serves that read and the read hosts serve none

### Requirement: A consistent read bypasses the read hosts and the window
`cache.Client` SHALL expose `GetConsistent`, which reads the writer whatever the window says. Memory
clients SHALL answer it exactly as `Get`, having no replicas to lag behind them.

It SHALL be used for a read-modify-write of a shared value, and for a read whose staleness keeps
changing the remediation served after the window has elapsed. Both Range-index reads qualify and
SHALL use it: `readRangeIndex`, because `ApplyRangeBatch` rewrites what it returns and a stale base
writes a truncated blob back for every instance, and `hydrateRangeMembership`, because
`storeRangeMembership` memoises the result as `lastRangeIndex` and serves it on every request until
the blob next changes. Both run once per update interval, so neither adds per-request cost.

The per-request lookup (`LookupCachedRemediation`) SHALL NOT use it. That path is what the read hosts
are for.

#### Scenario: A consistent read ignores a lagging read host
- **WHEN** the writer holds a value, the read host does not, and `GetConsistent` is called for it
- **THEN** the writer's value comes back and the read host serves no `GET`

#### Scenario: A range batch does not truncate the shared index
- **WHEN** the writer holds a Range index with an existing CIDR, the read host has not received it,
  and `ApplyRangeBatch` adds a second CIDR
- **THEN** the index on the writer holds both CIDRs
