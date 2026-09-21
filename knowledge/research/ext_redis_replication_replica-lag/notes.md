# Replica lag

Official Redis replication is **asynchronous by default**. A write that returns on the master is not guaranteed to be visible on a replica yet. Optional `WAIT` can wait for replica acknowledgements; it does not make Redis a strongly consistent store.

This plugin’s Redis cache writes on the writer and reads on `nextReader()` only. It does not send `WAIT`. It does not retry a replica miss or replica error on the writer.

## Official default

Redis uses asynchronous replication by default. The master does not wait for a command to be processed by replicas. Replicas acknowledge the amount of data they have processed periodically.

Replicas may serve read-only queries while the master remains the write target. A replica that is still catching up (or serving the old dataset during initial sync, when configured) can answer a GET that does not yet include a just-completed master SET.

Owner: [Redis replication](https://redis.io/docs/latest/operate/oss_and_stack/management/replication/). Extract: `.sources/replication.md`.

## Optional WAIT

`WAIT numreplicas timeout` blocks the current client until previous writes on that connection are transferred and acknowledged by at least `numreplicas` replicas (or the timeout). When `WAIT` returns, those writes are guaranteed to have been received by the number of replicas it returns. `WAIT` does not turn Redis into a CP / strongly consistent store.

Owner: [WAIT](https://redis.io/docs/latest/commands/wait/). Extract: `.sources/wait.md`.

This plugin’s cache Client never calls `WAIT`. Inference (`authority: inference`): a Get/MGet on a `LapiRedisReadHosts` replica after a writer Set can miss or return a prior value until that replica applies the replication stream.

## What this product does

`redisCache.set` / `delete` use `writer`. `get` / `getMany` call `nextReader()` only (writer when the reader list is empty; otherwise a read-host pointer, round-robin). Miss and replica error are not retried on the writer.

Owner: this worktree `pkg/cache/cache.go` (`nextReader`, `get`, `getMany`, `set`). Extract: `.sources/cache-next-reader.md`.

## Not this leaf

- Official `SET EX 0` rejection: `ext_redis_commands_set-ex-zero/`.
- README knob wording (outage vs lag): explore decision, not this finding.
