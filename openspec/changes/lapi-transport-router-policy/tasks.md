## 1. Bouncer policy (Part 1)

- [ ] 1.1 Add `lapiFailureAction`, `redisUnreachableBlock`, and live TTL fields to `Bouncer`; resolve LAPI failure action via `configuration.EffectiveFailureAction` in `bouncer.New`
- [ ] 1.2 Wire `bouncer` request paths to use bouncer-held policy instead of `lapiClient.LapiFailureAction()` / `RedisUnreachableBlock()`
- [ ] 1.3 Change `LiveLookup` signature to accept TTL; update call sites to pass bouncer TTL
- [ ] 1.4 Remove `defaultDecisionTimeout`, policy fields, and accessors from `lapi.Client`
- [ ] 1.5 Remove `lapiFailureAction`, `redisCacheUnreachableBlock`, `defaultDecisionSeconds`, and `streamStartupBlock` from `streamSettings` / `settingsFrom`; drop duplicates from `identity.go` where present

## 2. LapiTransport (Part 2)

- [ ] 2.1 Introduce `LapiTransport` with `*http.Client` and CAPI token handling (stop mutating identity `crowdsecKey` on the client for auth)
- [ ] 2.2 Store transport in `atomic.Value` on `Client`; route `client_http.go` through load/store
- [ ] 2.3 Implement `AdoptTransport(cfg)`: build, compare fields, `Store`, `closeIdle` previous
- [ ] 2.4 Call `AdoptTransport` from `OpenStream` after every successful open path (create, bind, wake, live joiner to owner key)
- [ ] 2.5 Remove `httpTimeoutSeconds` and LAPI TLS trio from settings hash

## 3. Logging (Part 3)

- [ ] 3.1 Extend `logInfo` with session key and `reason` on existing INFO lifecycle lines
- [ ] 3.2 INFO when transport replaced (field list) and when live joiner settings differ (ignored vs adopted lists)
- [ ] 3.3 Confirm reclaim table lines stay DEBUG (no level change in `pkg/reclaim`)

## 4. Tests

- [ ] 4.1 Reload changing only `lapiFailureAction`: same reclaimed `*lapi.Client`, `StreamFetches()` shows no extra `startup=true`
- [ ] 4.2 Reload changing only a TLS field: same `*lapi.Client`, transport replaced, cursor continuity (no extra `startup=true`)
- [ ] 4.3 Two routers with different `lapiFailureAction` on one cursor: each bouncer applies its own effective action
- [ ] 4.4 Per-router `defaultDecisionSeconds` in live mode (TTL argument honored per bouncer)
- [ ] 4.5 `waitStreamSessionInGrace` and `waitPluginStreamInGrace` still pass unchanged helpers
- [ ] 4.6 Regression: settings hash change still opens new incarnation (`metricsUpdateIntervalSeconds` or Redis host) per existing grace tests

## 5. Spec archive prep

- [ ] 5.1 After implement, fold deltas into `openspec/specs/` for `core_plugin_middleware_instance-reclaim`, `core_plugin_lapi_failure-action`, `core_plugin_lapi_connection`
- [ ] 5.2 Run `node .cursor/skills/sbs-dev-speclibrarian/scripts/validate-artifact-names.mjs` and `validate-spec-map.mjs --write` before archive phase

## 6. Verify

- [ ] 6.1 `go test ./pkg/lapi/... ./pkg/bouncer/...` and plugin tests touching stream reload
- [ ] 6.2 `openspec validate --change lapi-transport-router-policy --strict` (if available)
