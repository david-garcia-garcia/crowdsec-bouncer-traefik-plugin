---
url: https://www.dragonflydb.io/docs/command-reference/compatibility
title: Dragonfly API Compatibility
fetched: 2026-09-17
authority: official
---

Table tracks command-surface compatibility. "Fully supported" does not imply byte-for-byte identical behavior.

Scripting: EVAL fully supported; EVAL_RO fully supported; EVALSHA fully supported; EVALSHA_RO fully supported; SCRIPT LOAD fully supported; SCRIPT EXISTS fully supported; SCRIPT FLUSH partially supported (missing ASYNC, SYNC); SCRIPT DEBUG unsupported; SCRIPT KILL unsupported; FCALL unsupported; FUNCTION * unsupported.

String (related, not this finding’s owner): SET partially supported (missing IFDEQ, IFDNE, IFEQ, IFNE); SETNX fully supported.

Verification: Dragonfly v2.0.0; Redis 8.6.4.
