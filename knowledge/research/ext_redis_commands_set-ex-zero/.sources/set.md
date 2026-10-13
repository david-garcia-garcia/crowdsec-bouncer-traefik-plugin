---
url: https://redis.io/docs/latest/commands/set/
title: SET
fetched: 2026-09-18
authority: official
---

SET key value [NX | XX | …] [GET] [EX seconds | PX milliseconds | EXAT | PXAT | KEEPTTL].

EX seconds: Set the specified expire time, in seconds (a positive integer).

PX milliseconds: Set the specified expire time, in milliseconds (a positive integer).

Expiration options are mutually exclusive. Example uses EX 60, not EX 0.

The page does not name EX 0 or print an error string for a zero expire.
