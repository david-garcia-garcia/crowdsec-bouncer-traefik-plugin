---
url: pkg/cache/cache.go
title: redisCache nextReader get set
fetched: 2026-09-18
authority: source
ref: worktree pkg/cache/cache.go
---

nextReader returns writer when readers is empty; otherwise readers[counter % n].

get and getMany call nextReader only. Miss and unreachable are returned; no writer retry.

set and delete use writer, log Redis errors, and return. Client.Set / Delete are void.
