# Test coverage

1. [hard] Assertion does not prove the job — `pkg/lapi/zzz_session_test.go:21` — `testStreamConfig` fixes `LapiUpdateIntervalSeconds` at 60 and only varies `LapiMetricsIntervalSeconds`; `TestSessionKey_SameLapiKeySharesCursorAndRedisHash`, `TestOpenStream_LiveMetricsMismatchSharesSilently`, and `TestOpenStream_SleepingIntervalChangeWakesSameSlot` stay green if `SessionKey` hashed `lapiUpdateIntervalSeconds` again
   → Differ only on `LapiUpdateIntervalSeconds` and assert same `SessionKey` / one Client, and a sleeping `LapiUpdateIntervalSeconds` change Wakes the same slot
   Status: done
   Argument: stream key/share/Wake tests now differ on LapiUpdateIntervalSeconds
2. [hard] Edge case untested — `pkg/lapi/client.go:331` — `holders == 0` falls back to write-once `lapiScopeHeaders` (create-time first poll in `startStream` before `registerLiveHeaderScopes`); scope tests only call `streamQuery` after register
   → Assert the first LAPI stream request from a Country-mapped first router includes `country`
   Status: done
   Argument: added TestOpenStream_FirstCountryPollIncludesCountryBeforeRegister
