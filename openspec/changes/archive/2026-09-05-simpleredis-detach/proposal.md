## Why

On `master`, `pkg/simpleredis` still ships `LICENSE` and `SOURCE` that name `maxlerebourg/simpleredis` PR #8 as the source of truth, and the live spec requires the in-tree sources to match that outside branch. This repo now owns that client; remaining live pointers to an upstream pin will make later edits look like a fork.

## What Changes

- Delete `pkg/simpleredis/LICENSE` and `pkg/simpleredis/SOURCE`.
- Live spec and usage treat `pkg/simpleredis` as this plugin’s Redis client. Drop “copy of PR #8” and “SHALL match PR #8”.
- Keep the ban on importing published `github.com/maxlerebourg/simpleredis`.
- Keep research `ext_simpleredis_client_pooled-mget/` as historical; update the domain-index description so it is not a live pin.
- Do not change GET/SET/DEL/MGET/Close behaviour. Do not rewrite archived OpenSpec folders.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_cache_redis_in-tree-client`: first-party `pkg/simpleredis`; no requirement that sources match an outside simpleredis PR. Published-module import remains forbidden.

## Impact

- `pkg/simpleredis/LICENSE`, `pkg/simpleredis/SOURCE`
- `openspec/specs/core_cache_redis_in-tree-client/spec.md`
- `knowledge/devdocs/core_cache_redis.md`
- `knowledge/research/index_ext_simpleredis.md` (description only)
- Not **BREAKING**. Runtime API and operator Redis keys stay.
