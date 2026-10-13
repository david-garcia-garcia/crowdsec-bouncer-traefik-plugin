---
url: vendor/github.com/leprosus/golang-ttl-map/map.go
title: Heap.Set
fetched: 2026-09-18
authority: source
ref: worktree vendor leprosus golang-ttl-map Heap.Set
---

Heap.Set returns immediately when ttl == 0 (does not store).

ttl > 0 adds ttl seconds to now. ttl < 0 stores with Timestamp -1.
