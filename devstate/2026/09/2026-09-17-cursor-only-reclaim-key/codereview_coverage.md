# Test coverage

1. [hard] Assertion does not prove the job — `pkg/lapi/zzz_session_test.go:21` — `testStreamConfig` fixes `UpdateIntervalSeconds` at 60 and only varies `MetricsUpdateIntervalSeconds`; `TestSessionKey_SameLapiKeySharesCursorAndRedisHash`, `TestOpenStream_LiveMetricsMismatchSharesSilently`, and `TestOpenStream_SleepingIntervalChangeWakesSameSlot` stay green if `SessionKey` hashed `updateIntervalSeconds` again
   → Differ only on `UpdateIntervalSeconds` and assert same `SessionKey` / one Client, and a sleeping `UpdateIntervalSeconds` change Wakes the same slot
   Status: done
   Argument: stream key/share/Wake tests now differ on UpdateIntervalSeconds
2. [hard] Edge case untested — `pkg/lapi/client.go:331` — `holders == 0` falls back to write-once `decisionScopeHeaders` (create-time first poll in `startStream` before `registerLiveHeaderScopes`); scope tests only call `streamQuery` after register
   → Assert the first LAPI stream request from a Country-mapped first router includes `country`
   Status: done
   Argument: added TestOpenStream_FirstCountryPollIncludesCountryBeforeRegister
