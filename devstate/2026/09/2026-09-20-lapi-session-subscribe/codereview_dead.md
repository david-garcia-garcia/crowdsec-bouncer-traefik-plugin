# Dead

1. [hard] Leftover production path — `pkg/lapi/decisionstore.go:34` — `StoreKey` has no production caller after store Open moved to `newChildStore`
   ```
   func StoreKey(cfg *configuration.Config) string {
   	return decisionStoreKeyPrefix + SessionHex(cfg) + ":" + hashJSON(storeParamsFrom(cfg))
   }
   ```
   Grep `StoreKey`, `storeParamsFrom`, `storeParams`, `decisionStoreKeyPrefix` on `*.go`: definition only in `pkg/lapi/decisionstore.go`. Remaining hits are tests (`zzz_decisionstore_test.go`, `zzz_session_test.go`, `zzz_prepare_test.go`). `storeParams` / `storeParamsFrom` / `decisionStoreKeyPrefix` are only reached through `StoreKey`.
   → Delete `StoreKey`, `storeParams`, `storeParamsFrom`, and `decisionStoreKeyPrefix`; retarget tests to `SessionHex` / `newChildStore` / `Key`
   Status: done
   Argument: deleted StoreKey helper; tests use SessionHex; Redis prefix remains SessionHex
