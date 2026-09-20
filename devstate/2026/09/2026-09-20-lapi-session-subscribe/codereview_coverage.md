# Test coverage

Ticket job (requirement Desired 1–5 / proposal Why): stream/alone Open key is LAPI session only (not Redis); a second `New` on that session subscribes or Wakes the same Client and child DecisionStore (first-wins session-owned knobs with WARN, `startup=false`, do not fail `New`).

Proven: `TestSessionKey_SameLapiKeySharesCursorNotRedis` (`SessionKey` is `lapi:stream:`+`SessionHex`, Redis omitted), `TestOpenStream_DifferentRedisSharesClientAndStore` (same Client+store, ban hits, WARN `redisCacheHost` + holder names + second API key), `TestOpenStream_LiveMetricsMismatchSharesAndWarns` (create-time interval kept, WARN, first-create INFO), `TestOpenStream_SleepingRedisHostWakesSameSlot` (same Client, `startup=false`, store pointer kept). Reverting the Redis hash on `SessionKey` would fail those tests.

1. [hard] Critical path untested — `pkg/lapi/client.go:190` — Sleep must not Close the child store (this change retargeted Close to Close the store); `TestOpenStream_SleepingRedisHostWakesSameSlot` (`pkg/lapi/zzz_session_test.go:360`) only asserts pointer equality on a memory store (Close is a no-op); `TestOpenLive_LastHolderGraceClosesRedisPool` waits past grace. `(none)` that Lookup still hits while sleeping.
   → Redis Open, Put a ban, cancel last holder, Lookup during grace is a hit (then after grace unreachable)
   Status: done
   Argument: TestOpenStream_SleepKeepsChildRedisStore Lookup hit while Sleeping
2. [hard] Critical path untested — `pkg/lapi/client.go:144` — `create()` Closes the store if `startStream` fails (alone `getToken`); test: `(none)`
   → Alone Redis `New` with a failing CAPI login returns the error and a later Lookup on that store is unreachable
   Status: skipped
   Argument: New does not return the local store on startStream fail; TestClientClose_ClosesChildRedisStore already proves Redis Close → unreachable. No seam without leaking the store.
3. [hard] Assertion does not prove the job — `pkg/lapi/liveholders.go:28` — distinct-name set / two ctxs one alias; `TestOpenStream_TwoRoutersOneAliasOneNameOnWarn` (`pkg/lapi/zzz_session_test.go:732`) uses `strings.Count(..., `"same-alias"`) < 1` (same as Contains) and never asserts `len(nameByCtx)==2`. A list of duplicate names or a single `ownerName` stays green.
   → Assert two constructor contexts and the WARN `holderNames` JSON array contains the alias exactly once
   Status: done
   Argument: len(nameByCtx)==2 and middlewareNames JSON array contains the alias once
4. [judgement] Happy path only — `pkg/lapi/sessionresidue.go:38` — `ignoredFields` WARNs host and `updateIntervalSeconds` only; untested arms are `redisCacheEnabled` / `redisCachePassword` (spec: field name, never the secret) / `redisCacheDatabase` / `redisCacheReadHosts` / `metricsUpdateIntervalSeconds` / `updateMaxFailure` / `crowdsecCapiScenarios`
   → One subscribe WARN per remaining named field (password mismatch must list `redisCachePassword` and must not contain the secret), or skip unreachable
   Status: skipped
   Argument: judgement; host and interval already prove the compare loop; remaining arms are the same ignoredFields path.
