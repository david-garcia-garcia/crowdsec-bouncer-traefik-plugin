# upstream#370

- title: Stream poll lease is never stored when updateIntervalSeconds is 1
- state: CLOSED
- url: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/370
- created: 2026-08-03T11:47:21Z
- updated: 2026-08-07T17:11:55Z
- labels: (none)

## Body

### Summary

With `updateIntervalSeconds: 1`, the stream poll lease is never stored, so the guard that makes a single node poll LAPI per interval silently does nothing and **every** bouncer instance polls LAPI on **every** tick.

`updateIntervalSeconds: 1` is a supported value: `pkg/configuration/configuration.go` validates it as `>= 1`.

### Details

`handleStreamCache` takes a lease so that only one node polls LAPI per interval, and stores it for `updateInterval - 1` seconds:

https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/main/bouncer.go#L644

```go
bouncer.cacheClient.Set(cacheTimeoutKey, cache.NoBannedValue, bouncer.updateInterval-1)
```

At `updateInterval == 1` that duration is `0`, and neither cache backend stores a key with a zero TTL:

- **local cache** — `golang-ttl-map` returns early without storing:
  ```go
  func (h *Heap) Set(key string, value interface{}, ttl int64) {
      if ttl == 0 {
          return
      }
  ```
  (`vendor/github.com/leprosus/golang-ttl-map/map.go:113`)

- **redis** — `simpleredis` sends `SET <key> <value> EX 0` (`vendor/github.com/maxlerebourg/simpleredis/simpleredis.go:103`), which redis rejects with `ERR invalid expire time in 'set' command`. The `SET` fails outright.

Either way the next `Get(cacheTimeoutKey)` is a miss, so the lease never suppresses anything.

### Impact

Silent. Nothing errors on the local cache, and on redis it surfaces only as a `cache:setDecisionRedisCache` log line. A single-instance deployment behaves correctly and only pays a redundant poll, so this does not show up in single-node testing — the cost appears with several bouncers against a shared redis, where the intended one-poll-per-interval becomes N-polls-per-interval against LAPI.

### Suggested fix

Floor the lease duration at 1 second. At an interval of 1 the lease can then outlive a tick that fires slightly early and cost one skipped poll, which is preferable to every node polling every tick.

### Notes

Also worth considering separately: `redisCache.set` logs the failure but callers cannot distinguish "stored" from "not stored", which is why this failed quietly on redis too.
