# Dead

1. [hard] Leftover production path — `pkg/appsec/client_http.go:85` / `pkg/lapi/client_http.go:142` — `AdoptTransport` has no callers outside tests after `Open` / `OpenStream` / `OpenLive` stopped adopting and opened a new Client on knob change
   → Delete both `AdoptTransport` methods (and `fieldsDiffer`, only they call it); drop `TestReportMetricsWindowSurvivesAdoptTransport` and the remaining session adopt call
   Status: skipped
   Argument: test-only leftovers kept as migration shims; not applied unattended this pass.

   Grep `AdoptTransport`: definitions in `pkg/appsec/client_http.go` and `pkg/lapi/client_http.go`; remaining hits `pkg/lapi/zzz_session_test.go` and `pkg/lapi/zzz_metrics_test.go`.

2. [hard] Leftover production path — `pkg/decisionscope/lookup.go:68` — `StreamScopeList` has no callers after `streamQuery` moved to `c.streamScopeQuery` / `StreamScopeQuery`
   → Delete `StreamScopeList`; poll via `StreamScopeQuery(cfg.CrowdsecLapiStreamScopes)`
   Status: skipped
   Argument: test-only leftovers kept as migration shims; not applied unattended this pass.

   Grep `StreamScopeList`: definition only in `pkg/decisionscope/lookup.go` (no tests).

3. [hard] Leftover production path — `pkg/lapi/session.go:92` — `SessionKey` / `SessionPrefix` have no callers outside tests after `OpenStream` moved to `OwnershipKey`
   → Delete `SessionKey` and `SessionPrefix`; assert Open identity via `OwnershipKey`
   Status: skipped
   Argument: test-only leftovers kept as migration shims; not applied unattended this pass.

   Grep `SessionKey` / `SessionPrefix`: production is the pair of definitions (`SessionKey` is the only production caller of `SessionPrefix`); remaining hits `pkg/lapi/zzz_session_test.go`.

4. [hard] Leftover production path — `pkg/lapi/identity.go:142` — `Key` has no callers outside tests after `OpenLive` moved to `OwnershipKey`
   → Delete `Key`; assert via `OwnershipKey` / `SessionHex`
   Status: skipped
   Argument: test-only leftovers kept as migration shims; not applied unattended this pass.

   Grep `Key(`: production `lapi.Key` is the definition only (`appsec.Key` is a different function and still used by `appsec.Open`); remaining `lapi.Key` hits `pkg/lapi/zzz_session_test.go`.

5. [hard] Leftover production path — `pkg/lapi/client.go:58` — `Client.decisionScopeHeaders` is written in `New` and never read after `snapshotLiveHeaderScopes` was removed
   → Drop the field and the `New` assignment; tests already drive `streamScopeSet`
   Status: skipped
   Argument: test-only leftovers kept as migration shims; not applied unattended this pass.

   Grep `decisionScopeHeaders` in `pkg/lapi`: field plus `New` write; remaining hits tests (`zzz_ipcachekey_test.go` assigns it; `zzz_scopeunion_test.go` / `zzz_decisionstore_test.go` name the config knob).
