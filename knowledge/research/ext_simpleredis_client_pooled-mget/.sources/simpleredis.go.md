---
url: https://github.com/maxlerebourg/simpleredis/blob/f8801cc098d2ae1743a6f82cb1e60a97e9461b7f/simpleredis.go
title: simpleredis.go (pool-redis-connections)
fetched: 2026-09-05
authority: source
ref: github.com/maxlerebourg/simpleredis@f8801cc098d2ae1743a6f82cb1e60a97e9461b7f:simpleredis.go
---

Package supports GET, MGET, SET, DELETE, and TTL on keys.

Error string constants: RedisUnreachable, RedisMiss, RedisTimeout, RedisNoAuth, RedisIssue (`redis:unreachable` / `miss` / `timeout` / `noauth` / `issue?`).

Pool constants: maxIdleConns=8, idleTimeout=30s, dialTimeout=2s, ioTimeout=1s.

SimpleRedis fields: host, pass, database, mu sync.Mutex, idle []*pooledConn.

Init stores host, pass, database.

Get: exec GET name; require len(values)==1 else errIssue.

MGet: empty names return nil,nil; else MGET + names; require len(values)==len(names); missing keys stay nil slots (readBulk $-1 continues without writing).

Set: exec SET name data EX <duration>; return reply error.

Del: exec DEL name; return reply error.

exec: borrow; do; release. If err and reused and not reusable, dial fresh and retry once. Newly dialled connections are not retried.

borrow: LIFO from idle; skip/close entries older than idleTimeout; else dial.

release: if not reusable, close. Else if idle already at maxIdleConns, close. Else append (LIFO).

dial: TCP Dialer Timeout dialTimeout. If pass!="", AUTH once. If database!="", SELECT once. Handshake failure closes the conn.

do: SetDeadline(now+ioTimeout); writeCommand; readReply. I/O without a clean reply → not reusable.

writeCommand: RESP array `*n` then `$len` + bytes per arg.

readReply: `+`/`: ` → [][]byte{payload}; `-` → replyError (clean); `$` bulk; `*` array of bulks.

replyError: prefixes NOAUTH, WRONGPASS, NOPERM, ERR Client sent AUTH → errNoAuth; else errors.New(text).

ioError: net.Error Timeout → errTimeout; else errUnreachable.
