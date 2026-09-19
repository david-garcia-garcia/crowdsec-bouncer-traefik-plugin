# The writer pin does not cover decisions another instance wrote

IssueKey: 2026-09-18-cache-ttl-guard-and-read-your-writes
Size: large
Action: note

## Why this follow-up

The pin added by this change is read-**your**-writes: `redisCache` records the keys **this** client
wrote and routes reads of those keys to the writer for a bounded window. That closes the window the
ticket named, because in a single-instance deployment the stream poller and the request path share
one `redisCache`.

It does not close the multi-instance case. `handleStreamCache` (`pkg/lapi/client_stream.go:74-99`)
is a lease: exactly one instance wins and fetches the stream delta, and the losers do not write those
decisions at all. Instance B therefore has nothing pinned for an IP that instance A has just banned,
so B's request path reads it from a read host on the normal round-robin. If that host lags, B serves
the request A already decided to block — the same outcome the ticket describes, reached by a
different route.

## Why it was not taken

Closing it means routing the per-request lookup to the writer for every instance that did not win
the lease, which is writer-only reads for all but one instance. The ticket forbids exactly that:
`RedisCacheReadHosts` exists to carry the per-request lookup load. There is no way to know locally
that a key another process wrote is fresh without asking the writer.

The honest framing is that this is replication lag, not read-your-writes, and it is bounded by the
operator's replica health rather than by anything the plugin can do. A deployment that cannot
tolerate it should point `RedisCacheReadHosts` at the primary or leave it empty, which is already
configurable today and needs no code.

## Risks

An operator reading "read-your-writes" on the PR could assume the guarantee is deployment-wide. It
is per-instance. With several Traefik instances against one Redis primary plus replicas, the window
survives for every instance except whichever one won the lease that tick.

## Context

- Lease winner writes: `pkg/lapi/client_stream.go:80-98`, `pkg/lapi/client_decisions.go:24-54`
- Lease losers only hydrate: `pkg/lapi/client_stream.go:84-89`
- Round-robin read for an unpinned key: `pkg/cache/cache.go` `readerFor` → `nextReader`
- Existing operator escape hatch: leave `redisCacheReadHosts` empty, or point it at the write host
