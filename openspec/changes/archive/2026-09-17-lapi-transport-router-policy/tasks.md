## 1. Narrow reclaim hashes

- [x] 1.1 Drop `LapiFailureAction`, `RedisCacheUnreachableBlock`, `DefaultDecisionSeconds`, `StreamStartupBlock`, `HTTPTimeoutSeconds`, and the three LAPI TLS fields from `streamSettings` / `settingsFrom` and from live/none `identity` / `IdentityHex`
- [x] 1.2 Leave intervals, Redis host/auth/db/enabled, `updateMaxFailure`, CAPI scenarios, and `decisionScopeHeaders` as first-wins hash fields
- [x] 1.3 Keep `StreamStartupBlock` write-once on Client at `startStream`; first incarnation keeps it

## 2. Transport on atomic.Value

- [x] 2.1 Extract unexported `transport` in `pkg/lapi/client_http.go` (HTTP client, header, CAPI token)
- [x] 2.2 Store it on `Client` as `atomic.Value`; delete the plain `httpClient` field; `getToken` writes the token on the stored transport
- [x] 2.3 Add `AdoptTransport(cfg)` after `OpenStream` / `OpenLive` bind: Store new, `closeIdle` old
- [x] 2.4 Do not use `atomic.Pointer[T]`; do not make remaining write-once Client scalars mutable

## 3. Per-router policy on Bouncer

- [x] 3.1 Move `lapiFailureAction` (`EffectiveFailureAction`), `redisUnreachableBlock`, and `defaultDecisionTimeout` onto `Bouncer` from config
- [x] 3.2 Delete `Client.LapiFailureAction`, `Client.RedisUnreachableBlock`, and `NewTestLapiFailureActionClient`
- [x] 3.3 Add `defaultDecisionSeconds` to `LiveLookup`; delete `c.defaultDecisionTimeout`; Bouncer passes `config.DefaultDecisionSeconds`
- [x] 3.4 Point `ServeHTTP` / `applyLapiFailureAction` at Bouncer fields

## 4. Logging

- [x] 4.1 `logInfo` includes session key (`SessionKey` stream/alone, `Key` live/none) and `reason` (`started|sleeping|waking|closed`)
- [x] 4.2 INFO for transport replace (named fields) and for a live joiner whose remaining settings differ (`ignored` vs `adopted`)
- [x] 4.3 Leave `reclaim_put` / `reclaim_reclaim` / `reclaim_dispose` at DEBUG

## 5. Tests

- [x] 5.1 Same Client + no extra `startup=true` fetch after a failure-action-only reload
- [x] 5.2 Same Client + new transport after a TLS-only reload
- [x] 5.3 Two bouncers apply distinct failure actions
- [x] 5.4 Per-router live TTL
- [x] 5.5 Existing `waitStreamSessionInGrace` / `waitPluginStreamInGrace` still pass

## 6. Verify

- [x] 6.1 `go test` for `pkg/lapi`, `pkg/bouncer`, and root plugin tests
- [x] 6.2 Grep live product paths (not `openspec/changes/archive/`, not `devstate/`) for `LapiFailureAction()`, `RedisUnreachableBlock()`, `NewTestLapiFailureActionClient`, and `atomic.Pointer`
