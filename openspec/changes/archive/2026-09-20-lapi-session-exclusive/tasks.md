## 1. Exact Peek on vendor table and shim

- [x] 1.1 Add exported `State` (`Awake`, `Asleep`) and `(*Table).Peek(key) (any, State, bool)` on vendored `traefik-middleware-utilities/reclaim/table.go` (no wait on busy; no bind/Wake/grace stop)
- [x] 1.2 Re-export `State`, `Awake`, `Asleep`, and `Peek` on `Default()` from `pkg/reclaim` (`zzz_` tests for awake/asleep/miss/busy). Do not export `PeekLivePrefix` or `View`. Do not fork `table.go` into `pkg/reclaim`
- [x] 1.3 Keep `knowledge/debt/2026-09-20-upstream-reclaim-peek.md` as the CI vendor-restore / upstream Peek follow-up. Do not skip Peek

## 2. DecisionStore key, createdBy, streamReady

- [x] 2.1 Change `StoreKey` to `decisionstore:` + SessionHex only. Invert `TestStoreKey_DifferentRedisHostsIsolate` and the store half of `TestOpenStream_DifferentRedisIsolatesClientAndStore`
- [x] 2.2 Add write-once `createdBy` on `Store`; pass Traefik name into `OpenDecisionStore` / store `Open` create()
- [x] 2.3 Add `streamReady` and `streamPollInFlight` `int64` on `Store` with `LoadInt64` / `StoreInt64` / `CompareAndSwapInt64`. They own the CrowdSec cursor+applied cache, not this HTTP client. New Client must not zero them. Set `streamReady` on the `handleStreamCache` success path.

## 3. Exclusive name before Open

- [x] 3.1 In `OpenStream` / `OpenLive`, Peek the store key before Open. Hit + `createdBy != name` → Error log (owner, rejected, clears on Close, isolation is a second bouncer API key) and return error. Miss or same name → Open store then Client
- [x] 3.2 Invert different-name share tests (`TestOpenStream_LiveMetricsMismatchSharesSilently` `owner-mw`/`joiner-mw`, `TestOpenStream_HeaderMapMismatchSharesClient` `country`/`user`, `TestOpenStream_FailureActionOnlyKeepsClient` `first`/`test`) to fail the second name, or retarget to one name when they mean many routers / reconfigure. Redis-reload tests that use `first`/`reload` MUST use one name
- [x] 3.3 Confirm failed `New` still cancels `plugin.go` bindCtx. Client Close still must not Close the store. AppSec reclaim unchanged

## 4. Store poll skip and warm-store startup

- [x] 4.1 `handleStreamTicker` and Wake skip when store `TryBeginStreamPoll` fails. No Client IO context. `sendQuery` stays `http.NewRequest`. Sleep does not wait or cancel Do
- [x] 4.2 Close stops tickers and `closeIdle` only. `drainMetrics` unchanged
- [x] 4.3 `lapi.New` reads store `streamReady`: non-zero → `isCrowdsecStreamStartup = 0`. Empty store / mode-change SessionHex stays 1. Live/none: exclusive name only; no stream startup flag

## 5. Verify

- [x] 5.1 `go build ./...`, `go vet ./...`, `go test ./pkg/lapi ./pkg/reclaim ./pkg/decisionstore -count=1`, `go test . -count=1`, `golangci-lint run ./...`
