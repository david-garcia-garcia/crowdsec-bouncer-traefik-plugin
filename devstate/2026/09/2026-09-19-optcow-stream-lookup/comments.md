# PR comments
PR: https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/118 #118

- [x] comment chat-store-split @human  RETHINK
  Quote: Wrong domain separation. Shared Client only switches cache (Redis or memory). Need RedisStore vs MemoryStore: Redis uses cache, memory uses the COW map, so Client does not branch liveTick vs Set.
  Propose: accept — OpenSpec regenerated for store split: `streamStore` on `DecisionStore` (redis → `cache.Client`, memory → COW `map[string]liveSlot{word,expiresAt}`); Put/Delete/BeginTick/PublishTick/Lookup; Redis tick no-ops; remove `Client.liveTick` / `UsesLiveSnapshot` / bouncer branch; intern overflow Warn + kind-only word, no `LiveSlot.Leftover`; `cache.Client` stays lease/range-index/live-nonly; benchmarks vs `origin/master`. Implement replaces bolt-on (tasks reset unchecked).
  Implement: Replaced bolt-on with `streamStore` on `DecisionStore` (`streamstore.go`, `client_lookup.go`); removed `livesnapshot.go`/`Client.liveTick`; bouncer uses `LookupStreamRemediation`; memory overflow Warn + kind-only word; tests/benches updated (584ff695).
  Reply: Landed as `pkg/decisionstore.Store` engines (`memoryEngine`/`redisEngine`); no Client cache branch, no liveStore, no stream lease; `pkg/cache` deleted; utilities v1.0.5; overflow Warn + origin id 0. GitHub #5747561707.
  Persist: none (destBranch note stays on requirement.md; no devdocs owner for origin/HEAD)
