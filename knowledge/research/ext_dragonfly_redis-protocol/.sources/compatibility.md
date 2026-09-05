---
url: https://www.dragonflydb.io/docs/command-reference/compatibility
title: Dragonfly API Compatibility
fetched: 2026-09-05
authority: official
---

Table tracks whether Dragonfly accepts a command and its documented options. "Fully supported" does not imply byte-for-byte identical behavior.

Connection: AUTH fully supported; SELECT fully supported.

Generic: DEL fully supported; TTL fully supported; SWAPDB unsupported.

String: GET fully supported; MGET fully supported; SET partially supported — Missing: IFDEQ, IFDNE, IFEQ, IFNE; SETEX fully supported.

Verification: Dragonfly v1.40.0; Redis 8.6.4.
