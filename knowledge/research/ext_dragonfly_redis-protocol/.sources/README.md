---
url: https://github.com/dragonflydb/dragonfly/blob/e94300e6990093ec093cfb00d60c2e77ea4907e4/README.md
title: dragonfly README (v1.40.2)
fetched: 2026-09-05
authority: source
ref: github.com/dragonflydb/dragonfly@e94300e6990093ec093cfb00d60c2e77ea4907e4:README.md
---

Fully compatible with Redis and Memcached APIs; no code changes to adopt.

Redis-specific arguments: port default 6379; requirepass default ""; dbnum = max databases for SELECT; Dragonfly Docker uses /data for snapshots.

Example: --requirepass=… --port 6379.

Expiration: ranges ~8 years. Millisecond deadlines (PEXPIRE, PSETEX, …) rounded to nearest second for deadlines greater than 2^28ms.

HTTP console on main TCP port 6379 by default; server recognizes Redis vs HTTP at connection initiation. Disable with --http_admin_console=false if the port is exposed.
