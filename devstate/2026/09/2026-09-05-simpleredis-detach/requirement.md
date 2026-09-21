# Requirement
IssueKey: 2026-09-05-simpleredis-detach

## Problem
`pkg/simpleredis` is treated as a pinned copy of an outside module. `LICENSE` and `SOURCE` still name `maxlerebourg/simpleredis` PR #8. Live spec and usage docs still require matching that upstream. This ticket drops those files and treats the in-tree package as owned here, with no upstream.

## Current (code)
- `pkg/simpleredis/LICENSE` is the Apache-2.0 text that travelled with the copy (`pkg/simpleredis/LICENSE`).
- `pkg/simpleredis/SOURCE` names github.com/maxlerebourg/simpleredis commit `f8801cc`, branch `pool-redis-connections`, PR #8, plus a local Close/timeout delta (`pkg/simpleredis/SOURCE`).
- `pkg/simpleredis/simpleredis.go` and `pkg/simpleredis/simpleredis_test.go` have no upstream URL, pin, or copyright header.
- Live spec `openspec/specs/core_cache_redis_in-tree-client/spec.md` says the Redis cache is an in-tree copy of simpleredis PR #8 and SHALL match that branch (`pool-redis-connections`, `Init`/`Get`/`Set`/`Del`/`MGet`).
- Usage packet `knowledge/devdocs/core_cache_redis.md` defines **In-tree SimpleRedis** as copied from PR #8, lists `pkg/simpleredis/SOURCE` under Key files, and says do not import the published module.
- Research `knowledge/research/ext_simpleredis_client_pooled-mget/` documents the outside repo at that pin (`knowledge/research/index_ext_simpleredis.md`).
- Archived changes `openspec/changes/archive/2026-09-05-in-tree-simpleredis-dragonfly-e2e/` and `openspec/changes/archive/2026-09-05-simpleredis-comms-review/` record how the copy and SOURCE note were added. Those folders are history.
- Runtime import is already `github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/simpleredis`. `go.mod` does not require `github.com/maxlerebourg/simpleredis`.

## Desired
- Delete `pkg/simpleredis/LICENSE` and `pkg/simpleredis/SOURCE`.
- Live codebase and live docs treat `pkg/simpleredis` as this repo’s Redis client. No remaining live pointer that an outside simpleredis repo is the source of truth or that sources must match PR #8.

## Affected
- `pkg/simpleredis/LICENSE`
- `pkg/simpleredis/SOURCE`
- `openspec/specs/core_cache_redis_in-tree-client/spec.md`
- `knowledge/devdocs/core_cache_redis.md`
- `knowledge/research/ext_simpleredis_client_pooled-mget/` and `knowledge/research/index_ext_simpleredis.md` (whether a live research leaf still names an upstream)

## Out of scope
- Changing this plugin’s Go module path (`github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin`).
- Relicensing the plugin or adding copyright headers inside `simpleredis.go`.
- Rewriting archived OpenSpec change folders.
- Replacing the client with go-redis or another library.
- Runtime behaviour of GET/SET/DEL/MGET/Close.

## Unknowns
- Whether dropping the subdirectory LICENSE is enough, given the repo root is already Apache-2.0 (`LICENSE`). Ticket asked to delete the file.

## Tensions
- Live spec currently requires the in-tree sources to match outside PR #8. The ticket forbids that remaining as a live rule.
- Research still describes `maxlerebourg/simpleredis` as an outside system this product relies on. After detach, that leaf is historical, not a live upstream pin.
