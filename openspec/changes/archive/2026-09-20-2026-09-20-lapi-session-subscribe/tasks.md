## 1. Stream session key

- [x] 1.1 Make stream/alone `SessionKey` `lapi:stream:` plus `SessionHex` only (drop Redis hash and the hash separator)
- [x] 1.2 Leave live/none `Key` hashing Redis store params and `MetricsUpdateIntervalSeconds`
- [x] 1.3 Cover two stream names on one LAPI key share one Client; two lapiKeys on one host stay two Clients

## 2. Store as Client child

- [x] 2.1 Construct `NewMemory` / `NewRedis` (`keyPrefix` = `SessionHex`) inside Client `create()`; stop `OpenDecisionStore` from `OpenStream` / `OpenLive`
- [x] 2.2 Close the store on the `create()` error path; Client Close Closes the store; Sleep/Wake do not
- [x] 2.3 Delete `decisionstore.Open` / `lapi.OpenDecisionStore` if unused; `StoreKey` MAY stay as a helper (not a sibling Open)
- [x] 2.4 Cover stream Redis disagreement shares one store; live Redis disagreement isolates; live metrics-interval split does not share a reclaim store (memory miss)

## 3. Subscribe WARN and holders

- [x] 3.1 Capture create-time residue (Redis knobs, intervals, `updateMaxFailure`, CAPI scenarios) on `create()`
- [x] 3.2 On `!created`, compare residue; WARN every ignored field name (never password value), distinct holder names, and that isolation needs a second bouncer API key; do not fail `New`
- [x] 3.3 Register constructor ctx → Traefik `name` after successful `OpenStream` / `OpenLive`; unregister on ctx Done (`AfterFunc`); WARN prints the distinct-name set
- [x] 3.4 Invert `TestOpenStream_DifferentRedisIsolatesClientAndStore` to share+WARN; invert `TestOpenStream_LiveMetricsMismatchSharesSilently` to WARN; do not WARN TLS/timeout or `decisionScopeHeaders`

## 4. Wake

- [x] 4.1 Wake a sleeping stream session on the same `SessionKey` with `startup=false` even when Redis or interval YAML changed; keep the live store; no memory↔Redis migrate
- [x] 4.2 Invert `TestOpenStream_SleepingRedisHostDoesNotOverlapPollers` to Wake+WARN the same slot; keep `TestOpenStream_SleepingIntervalChangeWakesSameSlot`

## 5. Operator surface

- [x] 5.1 First-create INFO (`reason=started`) says this LAPI key owns the process-wide stream and usage-metrics window; do not log `ignored` INFO for session-owned knobs
- [x] 5.2 README shared-session Note: one key in this instance = one ticker + one metrics window; Redis/interval disagreements ignored, not isolated; two processes are two tickers (docs only)
- [x] 5.3 Failed `New` after stream Open still releases the LAPI holder and Closes the child store (AppSec-fail-after-stream scenario)

## 6. Verify

- [x] 6.1 `go test ./pkg/lapi ./pkg/decisionstore ./pkg/bouncer` (and plugin constructor tests that Open LAPI)
- [x] 6.2 Grep live product paths (not `openspec/changes/archive/`, not `devstate/`) for sibling `OpenDecisionStore` on the constructor ctx and for stream `SessionKey` still hashing Redis
