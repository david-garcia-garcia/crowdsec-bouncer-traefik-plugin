# A swallowed Redis write failure reads back as "not banned"

IssueKey: 2026-09-18-cache-ttl-guard-and-read-your-writes
Size: large
Action: note

## Why this follow-up

`redisCache.set` (`pkg/cache/cache.go:255-257`) logs a failed `SET` and returns. `redisCache.delete`
(`pkg/cache/cache.go:262-264`) does the same. `Client.Set` and `Client.Delete` return nothing, so
`storeStreamDecision` (`pkg/lapi/client_decisions.go:37,51`) believes every decision in the stream
delta reached the cache.

This is the one place found during this change where a swallowed cache error genuinely changes
behaviour rather than only losing a log line. When a `SET` for a ban fails — Redis full, a write to a
read-only replica after a failover, a command timeout — the poller still marks the tick a success,
still clears `updateFailure`, and still leaves `isCrowdsecStreamHealthy` set. The request path then
reads that IP as a miss, and stream and alone mode read a miss as "no decision affecting this IP"
(`pkg/bouncer/bouncer.go:202-222`), so the ban is never served. Nothing retries it until the next
`startup=true` resync, because the stream delta only carries each decision once.

`CrowdsecLapiFailureAction` cannot cover it either: that path is reached from
`StreamHealthy() == false`, and a failed write never makes the stream unhealthy.

## Why it was not taken

Threading `error` through the cache API was #38's third deliverable and triage dropped it as
expensive plumbing that touches every call site for a caller that can only log. That verdict stands
for the general case, and this change was scoped to TTL semantics and read routing.

Closing this properly is not the general plumbing, though: it needs `Set` to tell the stream poller
that the delta did not land, so the poller can drop the `updated` lease and re-fetch with
`startup=true` rather than pretend the tick succeeded. That is a change to the poller's success
condition, which needs its own ticket and its own decision about how many failed writes should cost
a resync.

## Risks

A Redis write outage is silent and self-perpetuating: bans issued during it are lost until something
else forces a `startup=true` stream, and the plugin reports itself healthy throughout. The operator
sees `cache:setDecisionRedisCache...` at ERROR and nothing else.

## Context

- Swallowed at `pkg/cache/cache.go:255-257` and `pkg/cache/cache.go:262-264`
- Believed successful at `pkg/lapi/client_decisions.go:37,51,63,72`
- Read back as a miss at `pkg/decisionscope/lookup.go:76` and served as allow at
  `pkg/bouncer/bouncer.go:202-222`
- Tick still counted as a success at `pkg/lapi/client_stream.go:90-98`
