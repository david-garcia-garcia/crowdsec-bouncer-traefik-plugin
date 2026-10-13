# Dead

1. [hard] Test-only new symbol — `pkg/decisionstore/store.go:287` — `ScenarioName` has no callers outside tests; lapi tests call it to read interned names while lookup and metrics still use `OriginName` only
   Quote:
      ```
      func (s *Store) ScenarioName(id uint16) string {
      	return s.scenarios.Name(id)
      }
      ```
   Note:
      ```
      rg -n --glob "*.go" --glob "!vendor/**" ScenarioName
      pkg/decisionstore/store.go:287 definition
      Remaining hits: pkg/decisionstore/zzz_memory_test.go, pkg/lapi/zzz_origin_intern_test.go, pkg/lapi/zzz_ipcachekey_test.go
      Production excluding *_test.go: definition only. OriginName still has lapi/bouncer callers.
      ```
   Fix: Rename `ScenarioName` to `ScenarioNameForTest`; keep intern pack and `FillScenarioUntilMaxForTest`
   Status: done
   Argument: Renamed `ScenarioName` to `ScenarioNameForTest`; retargeted lapi and decisionstore tests; usage doc names the test seam.

2. [hard] Test-only new symbol — `pkg/decisionstore/pack.go:129` — `packedScenarioID` has no production caller besides `PackedScenarioIDForTest`, which is itself only test-called
   Quote:
      ```
      func packedScenarioID(word uint32) uint16 {
      	return uint16(word >> packedScenarioShift)
      }
      ```
   Note:
      ```
      rg -n --glob "*.go" --glob "!vendor/**" packedScenarioID
      pkg/decisionstore/pack.go:129 definition
      pkg/decisionstore/store.go:320 PackedScenarioIDForTest wrapper
      Remaining hits: pkg/decisionstore/zzz_pack_test.go, pkg/decisionstore/zzz_memory_test.go
      Production excluding *_test.go: definition plus PackedScenarioIDForTest. packedOriginID still has ActiveCounts.
      ```
   Fix: Inline the shift into `PackedScenarioIDForTest`; retarget same-package tests to that ForTest helper
   Status: done
   Argument: Inlined packedScenarioID shift into PackedScenarioIDForTest; same-package tests call that helper.
