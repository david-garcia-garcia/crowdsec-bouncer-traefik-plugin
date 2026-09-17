# Isolated cache Client

## Language

**Isolated cache**:
One `pkg/cache.Client` store per LAPI Client. Memory is a private TTL map on that Client.
_Avoid_: process `ttl_map`, shared `var cache`, cross-replica shared lease keys

## Overview

Construct a new `Client` on each LAPI Client. Do not restore a package-level map.

Redis/Dragonfly cache was removed: CrowdSec LAPI stream cursor is per bouncer row (hashed API key plus outbound IP LAPI sees), not per API key alone. A shared remote store keyed only by LAPI URL+key let replicas share stream lease `updated` and skip LAPI while missing deltas ([crowdsecurity/crowdsec#3726](https://github.com/crowdsecurity/crowdsec/issues/3726)). Each Traefik replica polls LAPI into its own in-memory map.

## How to use

- `Client.New(log)` — each Client owns a TTL map in-process.
- Logical keys are the client IP, `scope:value`, `range-index`, and stream lease `updated`; payloads are opaque strings. Ban/captcha/none codes live on `pkg/decisionscope`. Captcha grace is the gate cookie (`core_plugin_middleware_captcha-gate.md`), not cache keys.
- Same reclaim key → same LAPI Client → same cache Client (share-by-identity, not a process dump).
- `Client.Close()` is a no-op for memory. Call it from `lapi.Client.Close()` for symmetry.

## Pattern snippet

```go
c := &cache.Client{}
c.New(log)
```

## Key files

- `pkg/cache/cache.go`
- `pkg/lapi/client_stream.go` (stream lease `updated`)
- `pkg/lapi/session.go` (warn-and-wire, one poller per LAPI URL+key)

## Gotchas

- No cross-replica decision sharing: scale-out needs each replica to poll LAPI (or distinct bouncer keys / hosts per replica).
- Real-stack restart clears in-process cache; live TTL and stream poll repopulate from LAPI.
