# Dead

1. [hard] Leftover production path — `pkg/admission/admission.go:140` — `Gate.BackingOff` lost its last production callers: this diff deleted the two `c.gate.BackingOff()` checks in `appsec.Client.Query` (part.01) and `modsecurity.Client.Inspect` (part.04) together with the unreadable-body drop branch; only tests call it now
   Fix: Delete `Gate.BackingOff`; `pkg/admission` tests read `g.backingOff` in-package, and `pkg/appsec/zzz_gate_test.go:298` asserts through the `MsgBackoffStarted` / `MsgBackoffEnded` log lines it already counts
   Status: skipped
   Argument: outside diff; not applied unattended. `pkg/admission` is not in this diff, and admission-gate behaviour is owned by another ticket.
   Quote:
   ```
   // BackingOff reports whether the last transition logged was MsgStarted.
   func (g *Gate) BackingOff() bool {
   	if g == nil {
   		return false
   	}
   	g.mu.Lock()
   	defer g.mu.Unlock()
   	return g.backingOff
   }
   ```
   Note:
   ```
   grep -rn "BackingOff" --include=*.go (excluding .pin_diff, devstate, vendor)
   pkg/admission/admission.go:140            definition
   pkg/admission/zzz_admission_test.go       7 hits (test)
   pkg/appsec/zzz_gate_test.go:298           client.GateForTest().BackingOff() (test)
   removed by this diff: part.01.diff:98 (appsec Query), part.04.diff:129 (modsecurity Inspect)
   ```
2. [judgement] Test-only new symbol — `pkg/appsec/zzz_test_helpers.go:111` — `newUnknownLengthGetRequest` (renamed here from `newUnreadableGetRequest`) has one caller, `zzz_unknown_length_body_test.go:73`, but lives in a file without the `_test.go` suffix or a build tag, so it compiles into the plugin package; its name does not say test, unlike the helpers this diff added beside it (`stallingTestBody`, `newStallingTestBody`, `newStreamingTestRequest`, `newUnknownLengthTestRequest`). Judgement because the whole file is an older test-support convention (`zzz_test_helpers.go`, imports `testing`) that this diff did not create
   Fix: Rename to `newUnknownLengthGetTestRequest`, or move the new helpers into a `_test.go` file in `pkg/appsec`
   Status: done
   Argument: Fixed with Standards 1 / Nitpicks 1: renamed to `newStalledUnknownLengthGetTestRequest` and the file is now `zzz_test_helpers_test.go`.
   Note:
   ```
   grep -rn "\bnewUnknownLengthGetRequest\b" pkg/appsec
   pkg/appsec/zzz_test_helpers.go:111        definition (no _test.go suffix, no //go:build tag)
   pkg/appsec/zzz_unknown_length_body_test.go:73   only caller (test)
   ```
