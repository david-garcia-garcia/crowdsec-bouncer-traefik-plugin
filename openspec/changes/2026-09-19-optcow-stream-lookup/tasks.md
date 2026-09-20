## 1. DecisionStore (landed)

- [x] 1.1 `pkg/decisionstore.Store` with engine funcs bound at `NewMemory` / `NewRedis` (not a backend interface).
- [x] 1.2 Memory COW `map[string]uint32` + `map[string]int64`; BeginTick / PublishTick; live Put onto published maps when not ticking.
- [x] 1.3 Redis SimpleRedis inside `pkg/decisionstore` (writer+replicas, nextReader never retries writer, void SET/DEL, miss vs unreachable).
- [x] 1.4 Intern table on Store; overflow Warn + origin id 0; Pack/Unpack/`KindOriginString` in decisionstore.
- [x] 1.5 Range blob `cidr=kind` then origin on the next newline; membership on Store `atomic.Value`.
- [x] 1.6 `LookupRemediation` / `lookupHits` / `lookupKeys` / `HeaderScopeKey` / `IPCacheKey` in decisionstore.
- [x] 1.7 Delete `pkg/cache` as the DecisionStore bag (lease, leftover, `cache.Client`).
- [x] 1.8 Store methods do not nil-check `s` or engine funcs; Close twice only on a real Redis store.
- [x] 1.9 `go.mod` / vendor `traefik-middleware-utilities` v1.0.5 (do not re-patch `iplookup/helper.go`).

## 2. LAPI and bouncer (landed)

- [x] 2.1 Stream apply: BeginTick → Delete then Put → PublishTick; Range via `ApplyRangeBatch`.
- [x] 2.2 No `Client.liveTick`, `UsesLiveSnapshot`, `cache.Client.Acquire`, or `updated` lease.
- [x] 2.3 Live/none memo is Store Put; `LiveLookup` returns kind+origin fields.
- [x] 2.4 Bouncer: one Store lookup for live/stream/alone; LiveLookup kind+origin on miss.

## 3. decisionscope shrink (landed)

- [x] 3.1 Letters, PreferRemediation, RequestScopeValues, StreamScopeList, Normalize*, RemediationKind (first letter only) stay in decisionscope.
- [x] 3.2 Drop leftover U+001F, RemediationWithOrigin, RemediationOrigin, GetInt leftover path, MatchRangeFromIndex.

## 4. Spec refresh (this phase)

- [x] 4.1 FindSpecHost over catalog + change deltas; journal on `devstate/specs.md`.
- [x] 4.2 Rename `core_cache_client_decision-store` → `core_plugin_decisionstore_store`; REMOVED cache Redis, isolated-store, stream-lease leaves.
- [x] 4.3 Rewrite proposal/design/tasks and change delta spec.md files to the landed Store. Mark landed tasks [x].

## 5. Tests (landed)

- [x] 5.1 Unit tests for tick publish, expiry, delete-before-new, skip-Range-on-Ip-ban, Redis miss vs unreachable, intern overflow.
- [x] 5.2 `go test` for `pkg/decisionstore`, `pkg/lapi`, `pkg/decisionscope`, `pkg/bouncer`.
