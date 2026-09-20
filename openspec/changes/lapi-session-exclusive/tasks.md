## 1. Exact Peek on vendor table and shim

- [x] 1.1 Add exported `State` (`Awake`, `Asleep`) and `(*Table).Peek(key) (any, State, bool)` on vendored `traefik-middleware-utilities/reclaim/table.go` (no wait on busy; no bind/Wake/grace stop)
- [x] 1.2 Re-export `State`, `Awake`, `Asleep`, and `Peek` on `Default()` from `pkg/reclaim` (`zzz_` tests for awake/asleep/miss/busy). Do not export `PeekLivePrefix` or `View`. Do not fork `table.go` into `pkg/reclaim`
- [x] 1.3 Keep `knowledge/debt/2026-09-20-upstream-reclaim-peek.md` as the CI vendor-restore / upstream Peek follow-up. Do not skip Peek

## 2. DecisionStore key, createdBy, streamReady

- [ ] 2.1 Change `StoreKey` to `decisionstore:` + SessionHex only. Invert `TestStoreKey_DifferentRedisHostsIsolate` and the store half of `TestOpenStream_DifferentRedisIsolatesClientAndStore`
- [ ] 2.2 Add write-once `createdBy` on `Store`; pass Traefik name into `OpenDecisionStore` / store `Open` create()
- [ ] 2.3 Add `streamReady` `int64` on `Store` with `LoadInt64` / `StoreInt64`. Set it on the `handleStreamCache` success path. Expose a load for `lapi.New`

## 3. Exclusive name before Open

- [ ] 3.1 In `OpenStream` / `OpenLive`, Peek the store key before Open. Hit + `createdBy != name` → Error log (owner, rejected, clears on Close, isolation is a second bouncer API key) and return error. Miss or same name → Open store then Client
- [ ] 3.2 Invert different-name share tests (`TestOpenStream_LiveMetricsMismatchSharesSilently` `owner-mw`/`joiner-mw`, `TestOpenStream_HeaderMapMismatchSharesClient` `country`/`user`, `TestOpenStream_FailureActionOnlyKeepsClient` `first`/`test`) to fail the second name, or retarget to one name when they mean many routers / reconfigure. Redis-reload tests that use `first`/`reload` MUST use one name
- [ ] 3.3 Confirm failed `New` still cancels `plugin.go` bindCtx. Client Close still must not Close the store. AppSec reclaim unchanged

## 4. Client IO context and warm-store startup

- [ ] 4.1 Add Client `WithCancel` IO context. `sendQuery` and live lookups use `NewRequestWithContext`. Sleep and Close cancel it. Wake mints a new `WithCancel`
- [ ] 4.2 `drainMetrics` / `reportMetrics` POST with `context.Background()`. Keep `closeIdle`
- [ ] 4.3 `lapi.New` reads store `streamReady`: non-zero → `isCrowdsecStreamStartup = 0`. Empty store / mode-change SessionHex stays 1. Live/none: exclusive name only; no stream startup flag

## 5. Verify

- [ ] 5.1 `go build ./...`, `go vet ./...`, `go test ./pkg/lapi ./pkg/reclaim ./pkg/decisionstore -count=1`, `go test . -count=1`, `golangci-lint run ./...`
