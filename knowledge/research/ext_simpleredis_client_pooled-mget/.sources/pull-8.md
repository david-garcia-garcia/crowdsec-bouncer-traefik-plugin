---
url: https://github.com/maxlerebourg/simpleredis/pull/8
title: feat: pool redis connections and add MGet
fetched: 2026-09-05
authority: comment
---

Open PR. Branch pool-redis-connections. Author mathieuHa. Closes #7. Supersedes #9.

States: idle pool; AUTH and SELECT once per opened connection; MGet([]string) ([][]byte, error) with nil for missing keys; empty list no round trip; short MGET reply is redis:issue?.

Bugs fixed vs main (author’s list): Set/Del never read reply; timeout select/default never fires; rejected AUTH deadlock via unbuffered channel; RESP arrays instead of space-joined inline; bulk by length so newline values survive. Author’s GET example of newline truncation on main.

Design: LIFO; lazy idle reap; maxIdleConns 8 caps kept conns, never blocks; one retry on a pooled connection that dies mid-command.

Compatibility: Init/Get/Set/Del and error constants unchanged; MGet new. Callers: do not copy SimpleRedis by value (mutex); Set/Del now return previously swallowed errors (non-positive EX likely first sighting).

Testing claim: 12 tests; green via go test -race and yaegi test in a GOPATH layout “the way Traefik loads plugin sources”. CI added on this PR.

GitHub also listed merge-commit preview 70e56820b23ec895f93e3a7277402004f936d2a6; that is not the branch HEAD.
