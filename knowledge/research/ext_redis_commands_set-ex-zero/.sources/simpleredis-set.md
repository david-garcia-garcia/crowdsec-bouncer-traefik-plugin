---
url: vendor/github.com/david-garcia-garcia/traefik-middleware-utilities/simpleredis/commands.go
title: SimpleRedis Set
fetched: 2026-09-18
authority: source
ref: worktree vendor SimpleRedis Set
---

Set(ctx, name, data, duration) always execs SET name data EX <decimal duration>.

Duration is FormatInt as given. No guard for 0 or negative. No SET without EX.
