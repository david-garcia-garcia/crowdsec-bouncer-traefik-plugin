---
url: https://github.com/maxlerebourg/simpleredis/blob/94fbffdc41f91d0b50ccecf8f77302ed9d4df342/simpleredis.go
title: simpleredis.go (main)
fetched: 2026-09-05
authority: source
ref: github.com/maxlerebourg/simpleredis@94fbffdc41f91d0b50ccecf8f77302ed9d4df342:simpleredis.go
---

Package comment: GET, SET, DELETE only. Same error string constants as PR #8. No MGet. No mutex. No pool. SimpleRedis is host, pass, database only.

genRedisArray joins params with spaces and appends `\r\n` (inline command, not RESP bulk args).

Every askRedis Dials TCP (2s), AUTH+SELECT if set, then the command, then Close. One connection per call.

SET/DEL switch arms send and do not read a reply. Set() and Del() call askRedis then `return nil`.

GET loop: select { time.After(1s) vs default: ReadLineBytes }. default always selected when the read is attempted immediately. Bulk payload is the next ReadLineBytes after the `$…` header — truncated at the first newline.

waitRedis: same select/default pattern; sends RedisTimeout or RedisNoAuth on `channel`. Set/Del pass `nil` as that channel.

No SetDeadline on the connection.
