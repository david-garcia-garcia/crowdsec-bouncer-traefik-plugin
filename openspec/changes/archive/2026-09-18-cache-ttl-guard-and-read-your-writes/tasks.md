# Tasks

## 1. Measure what today does

- [x] 1.1 Measure the in-memory backend with a zero and a negative TTL, on a fresh key and on a live one
- [x] 1.2 Measure the Redis backend against a real `redis:7-alpine`, capturing the exact error text
- [x] 1.3 Measure both backends on the lease verb
- [x] 1.4 Enumerate every production cache read path and mark which ones change the remediation served

## 2. Non-positive TTL is a no-op

- [x] 2.1 Failing-first tests: memory no-op, live entry untouched, no `SET` on the wire, lease not taken, no `EVAL` on the wire
- [x] 2.2 Guard `Client.Set` at the boundary
- [x] 2.3 Guard `Client.Acquire`, returning `cache:bad-ttl`
- [x] 2.4 Leave `Client.Delete` alone: no duration, nothing to guard

## 3. Read your own writes where it changes a decision

- [x] 3.1 Failing-first test: a read right after a write does not reach a lagging read host
- [x] 3.2 Failing-first test: a read right after a delete does not read the value back
- [x] 3.3 Failing-first demonstration: `LookupCachedRemediation` misses a just-stored ban
- [x] 3.4 Failing-first demonstration: `ApplyRangeBatch` truncates the shared index
- [x] 3.5 Record written keys and route `get` / `getMany` through `readerFor`
- [x] 3.6 Cap the recorded set and make overflow pin every read
- [x] 3.7 Add `Client.GetConsistent` and route `readRangeIndex` and `hydrateRangeMembership` through it
- [x] 3.8 Test that reads return to the read hosts once the window elapses
- [x] 3.9 Test that writing one key does not pin another

## 4. Gates

- [x] 4.1 `go build ./...`, `go vet ./...`
- [x] 4.2 `go test ./pkg/... -count=1`
- [x] 4.3 `go test . -count=1` (yaegi)
- [x] 4.4 `golangci-lint run ./...`
- [x] 4.5 `-race` in Docker over `./pkg/...`
- [x] 4.6 CI green on the PR head

## 5. Catalogue

- [x] 5.1 New spec leaf `core_cache_client_write-lifetime`
- [x] 5.2 Read-routing requirements on `core_cache_redis_utilities-client`
- [x] 5.3 Usage docs `core_cache_client.md` and `core_cache_redis.md`
- [x] 5.4 Debt note for the swallowed `redisCache.set` error, which stays out of scope
