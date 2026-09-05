## 1. Drop pin files and live spec pin

- [ ] 1.1 Delete `pkg/simpleredis/LICENSE` and `pkg/simpleredis/SOURCE`
- [ ] 1.2 Update `openspec/specs/core_cache_redis_in-tree-client/spec.md` first requirement to match the fold delta (Purpose already rewritten in propose)

## 2. Live docs

- [ ] 2.1 Update `knowledge/devdocs/core_cache_redis.md` Language and Key files: owned client, no SOURCE, keep published-module `_Avoid_`
- [ ] 2.2 Update `knowledge/research/index_ext_simpleredis.md` so the leaf is historical, not a live pin this product relies on

## 3. Verify

- [ ] 3.1 `go test ./pkg/simpleredis ./pkg/cache`
- [ ] 3.2 Grep live product paths (not `openspec/changes/archive/`, not `devstate/`) for `pkg/simpleredis/SOURCE` and “SHALL match simpleredis PR #8”
