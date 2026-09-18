---
url: https://redis.io/docs/latest/commands/wait/
title: WAIT
fetched: 2026-09-18
authority: official
---

WAIT numreplicas timeout blocks until previous write commands on this connection are transferred and acknowledged by at least numreplicas replicas, or until timeout milliseconds (0 = wait forever).

When WAIT returns, those previous writes are guaranteed to have been received by the number of replicas it returns.

WAIT does not make Redis a strongly consistent store. Failover can still lose an acknowledged write.

Clients must check the returned replica count against the level they demanded.

Example: SET foo bar then WAIT 1 0.
