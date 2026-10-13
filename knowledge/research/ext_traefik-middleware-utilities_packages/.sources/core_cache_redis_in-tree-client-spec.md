---
ref: openspec/specs/core_cache_redis_in-tree-client/spec.md@6548da47e933efe60309954be5f764f839b69e3f
title: core_cache_redis_in-tree-client
fetched: 2026-09-17
authority: ticket
---

Runtime SHALL NOT import `github.com/maxlerebourg/simpleredis`.
`pkg/simpleredis` MUST NOT be required to match an outside simpleredis repository or pull request.
`pkg/simpleredis` MUST NOT contain LICENSE or SOURCE pin files.
