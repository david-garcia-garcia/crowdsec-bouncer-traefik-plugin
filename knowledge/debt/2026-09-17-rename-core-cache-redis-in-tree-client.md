# Rename `core_cache_redis_in-tree-client` → `core_cache_redis_utilities-client`

IssueKey: 2026-09-17-upstream-reclaim-simpleredis
Size: large
Action: note

## Why this follow-up
The leaf `in-tree-client` names a `pkg/simpleredis` this change deletes. After the swap the client is the vendored utilities module.

## Why it was not taken
Archive folders and live specs still cite the current id. Unattended take is only small rows on files this run created.

## Risks
Later packets keep folding Redis-client rules into a leaf that says in-tree after the sources live under `vendor/`.
