---
url: https://www.dragonflydb.io/docs/managing-dragonfly/flags
title: Server Configuration Flags
fetched: 2026-09-05
authority: official
---

Flags via CLI (`dragonfly --port=6379`), --flagfile, env `DFLY_<flag>` (case sensitive), or CONFIG SET for some.

--port: Redis port. default 6379. 0 disables; -1 random.

--dbnum: Number of databases. default 16.

--requirepass: Password for AUTH. default "".

--cache_mode: default false.
