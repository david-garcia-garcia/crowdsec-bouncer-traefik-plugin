## 1. Cache acquire

- [x] 1.1 Add a narrow acquire on `pkg/cache.Client` (Redis `Eval` on writer+prefix; memory mutex around miss+Set). No poller logic. No SetNX. No `atomic.Pointer[T]`
- [x] 1.2 Cover Redis Eval-not-Get-then-Set and two-goroutine memory exactly-one-winner

## 2. DecisionStore

- [x] 2.1 Add `DecisionStore` in `pkg/lapi/decisionstore.go`: owns `cache.Client`, reclaim key `decisionstore:` + SessionHex + `:` + Redis-params hash, prefix `SessionHex` for every mode, Close hook = `cache.Client.Close()` only
- [x] 2.2 Open the store with `reclaim.OpenWithHooks` on the same Traefik `New` ctx from `OpenStream` / `OpenLive` / `New`. `Client` holds the store; `Cache()` returns `store.Cache()`
- [x] 2.3 Stop `Client.Close` / `Sleep` from calling `cache.Client.Close()`. Do not turn write-once Client scalars into mutable fields
- [x] 2.4 Point Client-literal tests at a store or helper. Keep Range hydrate from shared `range-index`

## 3. Stream lease

- [ ] 3.1 Replace `handleStreamCache` Get-then-Set with DecisionStore acquire. Keep 1s TTL floor
- [ ] 3.2 Cover two memory pollers one fetch and two Redis pollers one fetch

## 4. Share and isolate

- [ ] 4.1 Cover two live Clients (same LAPI + Redis, different `updateIntervalSeconds`) sharing one store
- [ ] 4.2 Cover different Redis hosts isolated; `decisionScopeHeaders` mismatch still shares; live prefix is SessionHex not IdentityHex; one Client Close leaves the sibling cache live

## 5. Spec naming and docs

- [ ] 5.1 Name `RedisCacheReadHosts` on the reclaim-key usage packet; keep `decisionScopeHeaders` off live/none identity
- [ ] 5.2 Remap `knowledge/devdocs/core_cache_client.md` Language/usage off isolated-per-Client
- [ ] 5.3 Update the utilities research sentence that says this cache does not need EVAL

## 6. Debt close

- [ ] 6.1 Delete `knowledge/debt/2026-09-17-shared-decision-store.md`
- [ ] 6.2 Mark the matching `issues.md` row `[x]` with `Taken:`. Leave `knowledge/debt/2026-09-17-cursor-only-reclaim-key.md`

## 7. Verify

- [ ] 7.1 `go test` for `pkg/cache` and `pkg/lapi` (not AppSec, not MetricsReporter rewrite)
- [ ] 7.2 Grep live product paths (not `openspec/changes/archive/`, not `devstate/`) for `atomic.Pointer` and for `Client.Close` still calling `cache.Client.Close`
