---
url: https://github.com/maxlerebourg/simpleredis/blob/f8801cc098d2ae1743a6f82cb1e60a97e9461b7f/simpleredis_test.go
title: simpleredis_test.go (pool-redis-connections)
fetched: 2026-09-05
authority: source
ref: github.com/maxlerebourg/simpleredis@f8801cc098d2ae1743a6f82cb1e60a97e9461b7f:simpleredis_test.go
---

In-process fake Redis speaks RESP arrays (readCommand). GET/MGET/SET implemented; other commands reply +OK.

TestGetHitAndMiss: hit returns value; missing returns RedisMiss.

TestConnectionIsReused: 25 sequential Get open 1 connection.

TestConcurrentCommandsStayWithinPool: 8 goroutines × 20 Get open at most 8 connections.

TestValueWithNewlinesSurvives: Set/Get of `10.0.0.0/8\n192.168.0.0/16\n172.16.0.0/12` round-trips intact.

TestMGetHitsMissesAndEmpty: MGet a,b,c with a/c present returns [t, nil, f]; MGet(nil) is nil,nil; still 1 connection.

TestMGetKeepsValuesWithNewlinesAligned: MGet of newline-bearing range-index plus two other keys stays aligned.

TestMGetRejectsShortReply: 2-element array for 3 keys → RedisIssue.

TestRejectedAuthIsReturned: -NOAUTH → RedisNoAuth on Get.

TestSetReturnsReplyError: Set with duration -1 against ERR integer reply surfaces that text (does not swallow).

TestDelSucceeds: +OK on Del is nil error.

TestUnreachableHost: 127.0.0.1:1 → RedisUnreachable for Get and MGet.

TestStaleConnectionIsRetried: close idle conn after first Get; second Get succeeds and opens a second connection.

No Yaegi or Traefik identifiers in this file.
