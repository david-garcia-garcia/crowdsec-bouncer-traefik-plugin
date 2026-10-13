# SET EX 0

Official Redis `SET` treats `EX seconds` as a **positive integer**. `EX 0` is therefore not a valid expire. `SETEX` is documented as equivalent to `SET key value EX seconds` and returns an error when `seconds` is invalid.

This plugin’s vendored utilities SimpleRedis `Set` always sends `SET … EX <n>` with the duration as given, including `0`. Memory `Heap.Set` no-ops when `ttl == 0`. Those two host behaviors stay split; this leaf only owns the Redis command rule.

## Official expire rule

`SET` optional argument `EX seconds`: “Set the specified expire time, in seconds (a positive integer).” The same page requires `PX` milliseconds to be a positive integer.

Owner: [SET](https://redis.io/docs/latest/commands/set/). Extract: `.sources/set.md`.

`SETEX key seconds value` is “equivalent to `SET key value EX seconds`.” “An error is returned when `seconds` is invalid.”

Owner: [SETEX](https://redis.io/docs/latest/commands/setex/). Extract: `.sources/setex.md`.

Inference (`authority: inference`): `0` is not a positive integer, so official `SET … EX 0` is invalid and official `SETEX` with `seconds=0` is an error. Official pages do not print the exact `ERR invalid expire time` string.

## What this product sends

Vendored `SimpleRedis.Set` always appends `EX` and `strconv.FormatInt(duration, 10)`. Duration `0` is sent as `EX 0`. There is no skip, clamp, or omit-EX path.

Owner: this worktree `vendor/github.com/david-garcia-garcia/traefik-middleware-utilities/simpleredis/commands.go` (`Set`). Extract: `.sources/simpleredis-set.md`.

Memory TTL map `Heap.Set` returns without storing when `ttl == 0`. That is not Redis. Do not treat it as the Redis expire rule.

Owner: this worktree `vendor/github.com/leprosus/golang-ttl-map/map.go` (`Heap.Set`). Extract: `.sources/golang-ttl-map-set.md`.

## Dragonfly

e2e uses Dragonfly, not Redis. Dragonfly’s SET page documents `EX seconds` and does not state `EX 0`. Do not claim Dragonfly rejects or accepts `EX 0` from this leaf.

Owner: existing `knowledge/research/ext_dragonfly_redis-protocol/notes.md` (SET `EX` documented; no EX-0 clause).

## Not this leaf

- Replica lag after a primary write: `ext_redis_replication_replica-lag/`.
- How `pkg/cache` logs a Redis Set error and returns void: usage/spec, not this finding.
