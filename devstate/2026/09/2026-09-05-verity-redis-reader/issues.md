# Issues

- [ ] note large  spec `core_cache_redis_in-tree-client` scenario “MGet is available without cache calling it” still says `pkg/cache` uses `Get`/`Set`/`Del` for one key per request
  Why: `GetMany`/`MGet` already landed on `master`. This ticket does not retell that leaf.
