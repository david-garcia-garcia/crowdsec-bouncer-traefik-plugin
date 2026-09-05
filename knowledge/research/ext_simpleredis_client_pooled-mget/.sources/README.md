---
url: https://github.com/maxlerebourg/simpleredis/blob/f8801cc098d2ae1743a6f82cb1e60a97e9461b7f/README.md
title: README.md (pool-redis-connections)
fetched: 2026-09-05
authority: source
ref: github.com/maxlerebourg/simpleredis@f8801cc098d2ae1743a6f82cb1e60a97e9461b7f:README.md
---

Minimal Go Redis with get, mget, set, and delete. Password authentication. No external dependencies.

Connections are pooled: a command reuses an already authenticated connection when one is idle, so AUTH and SELECT are paid once per connection instead of once per command.

A SimpleRedis is safe for concurrent use and must not be copied once initialized.

Example: Init("redis:6379", "", ""); Set(key, []byte, 60); Get; Del. Comment lists redis:unreachable, redis:miss, redis:timeout as Get errors.

Does not mention Yaegi or Traefik.
