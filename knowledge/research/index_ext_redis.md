# ext / redis

## go-redis client
priority: normal
local: ext_redis_go-redis/
description: Surface and host constraints of the official Go Redis client — API shape, pooling knobs, Go version floor, and its mandatory unsafe/syscall imports.

## SET EX 0
priority: normal
local: ext_redis_commands_set-ex-zero/
description: Official Redis SET EX / SETEX rule that expire seconds must be a positive integer, and what this plugin still sends.

## Replica lag
priority: normal
local: ext_redis_replication_replica-lag/
description: Official Redis asynchronous replication and WAIT, and why a replica GET can miss a just-completed master SET.
