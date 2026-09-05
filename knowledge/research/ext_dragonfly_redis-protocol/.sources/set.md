---
url: https://www.dragonflydb.io/docs/command-reference/strings/set
title: Redis SET Command (Documentation)
fetched: 2026-09-05
authority: official
---

Syntax: SET key value [NX | XX] [GET] [EX seconds | PX milliseconds | EXAT | PXAT | KEEPTTL]

EX seconds sets expiration atomically with the value. Example: SET mykey "temporary-ex" EX 10 then TTL mykey → 10.

Returns OK on success. NX/XX miss returns (nil).
