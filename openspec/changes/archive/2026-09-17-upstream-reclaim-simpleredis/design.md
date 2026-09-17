## Context

See `proposal.md` Why. Dest `master` has `pkg/reclaim` (Default, OpenWithGrace, `*Wrapped`, Peek) and `pkg/simpleredis` (`Init`, no ctx). Utilities `v1.0.3` has Hooks, table-wide grace, `New(Config)`, and ctx commands. Yaegi loads this module plus `vendor/`. Peek/PeekLivePrefix are not on the upstream table (unexported `items`).

FindSpecHost:

```
verdicts:
  - { deltaId: redis-client, fold|new: new, spec-id: core_cache_redis_utilities-client, confidence: high, candidates: [core_cache_redis_in-tree-client, core_cache_redis_utilities-client] }
  - { deltaId: reclaim-table, fold|new: fold, spec-id: std_go_reclaim_context-lease, confidence: high, candidates: [std_go_reclaim_context-lease] }
  - { deltaId: appsec-open, fold|new: fold, spec-id: core_plugin_appsec_client, confidence: high, candidates: [core_plugin_appsec_client] }
  - { deltaId: lapi-grace, fold|new: fold, spec-id: core_plugin_middleware_instance-reclaim, confidence: high, candidates: [core_plugin_middleware_instance-reclaim] }
```

`core_cache_redis_in-tree-client` names the package this change deletes → rename in this change (legal 4th part `utilities-client`).

## Goals / Non-Goals

**Goals:**
- Stop owning a SimpleRedis fork; vendor utilities `v1.0.3`.
- Sync reclaim table sources to that tag; keep Peek on `pkg/reclaim`.
- Migrate LAPI/AppSec to Hooks; process table grace 30s.

**Non-Goals:**
- Adopting EVAL/MSetEX or other unused SimpleRedis commands.
- Threading `req.Context()` through `cache.Client`.
- Importing the reclaim module (would lose Peek).
- Patching `vendor/` of utilities.
- Merging `origin/main`.
- Importing `windowcounter`, `tokenbucket`, or other unused utilities packages.

## Decisions

1. **Vendor the module; delete `pkg/simpleredis`.** Catalog/local Yaegi already sees `vendor/github.com/leprosus/golang-ttl-map`. Same layout for utilities.
2. **Source-sync reclaim into `pkg/reclaim`.** Same import path. Add/keep `default.go` and Peek helpers in that package so they can read `items`. Do not `import` utilities/reclaim.
3. **Process table grace is 30s.** Production only used `OpenWithGrace(..., 30s)`. Tests that need zero grace construct or reset a table with that grace.
4. **Hooks at the call site.** `wrappedClient` becomes Hooks on `Open` / `OpenWithHooks`. Drop `*Wrapped`.
5. **Cache ctx is `context.Background()`.** Cache has no request ctx today.
6. **Keep this plugin’s dial 2s / command 1s** on `simpleredis.Config`. Do not take upstream 200ms/900ms defaults.
7. **Pin `v1.0.3`.** Do not follow utilities `master`.
8. **Rename the Redis-client spec** in this change. Archive keeps the old id.

## Risks / Trade-offs

- [Yaegi fails to load the vendored utilities package] → Same vendor path as ttl-map; utilities is Yaegi-tested. Mock e2e on this branch proves load.
- [Source-synced reclaim drifts again] → Table tests come with the sync; Peek stays a small local file. Next bump is a version bump + file copy, not a silent fork of SimpleRedis.
- [30s table grace changes tests that assumed 10s Default + 30s put] → Only LAPI/AppSec used the 30s put; tests that pass `ResetForTestWith(0)` still need a zero-grace table helper.

## Migration Plan

No operator config change. Rollback is revert. Catalog users pick up the vendor tree with the next plugin release.
