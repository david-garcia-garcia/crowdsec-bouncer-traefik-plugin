## Context

See `proposal.md` Why. On DestBranch `389a33b`, four `pkg/lapi` test sites build `var buf bytes.Buffer`, hand `&buf` to `slog.NewJSONHandler`, and later read `buf.String()`. Three of those sites construct a `Client`; two construct it through `OpenStream`, which reaches `New` inside the reclaim open hook. `New` spawns `go client.handleMetricsTicker()` (`client.go:148`) and a 1s metrics ticker, and `handleMetricsTicker` logs at ERROR when the POST fails. A test cannot join that goroutine, and `Close` does not wait for it.

FindSpecHost:

```
verdicts:
  - { deltaId: test-log-sink, fold|new: new, spec-id: std_go_test_log-sink, confidence: high, candidates: [std_go_test_zzz-prefix, std_go_logger_slog-output, core_plugin_lapi_connection, core_plugin_lapi_usage-metrics] }
```

Search: family `std_go_test` has one leaf, `zzz-prefix`, whose unit is the test *filename* — not how a test captures output. `std_go_logger_slog-output` is the production logger's destination and format. The `core_plugin_lapi_*` leaves are production behavior; nothing in the captured traces says production is wrong. No existing leaf owns test log capture, so this is a new leaf under an existing family.

## Goals / Non-Goals

**Goals:**

- `go test -race ./pkg/lapi/` is silent on repeat runs.
- A test that reads captured log output cannot race a goroutine of the code under test, whatever that code spawns.
- Tests that open a real `Client` stop it before they assert, so no ticker outlives the test.
- Every existing assertion still runs.

**Non-Goals:**

- Any production `.go` change. If the traces had shown a production-owned shared object, the ticket says report it, not fix it here.
- Changing the `Race detector` job or the workflow `push` trigger.
- Deleting or weakening an assertion to make the detector quiet.
- Draining or joining the client's goroutines from a test (there is no such API, and adding one is production code).

## Decisions

1. **One sink type, not a mutex per test.** `syncLogSink` in `pkg/lapi/zzz_logsink_test.go`: `sync.Mutex` + `bytes.Buffer`, `Write` and `String` both under the mutex. Alternative: a `sync.Mutex` beside each `bytes.Buffer` — rejected, four copies of the same invariant and the next test copies the unsafe shape.
2. **The constructor hands back the logger and the sink** (`newTestLogSink(level)`), so no test holds a raw `bytes.Buffer` it could read directly.
3. **Convert all four sites**, including `captureTestStreamTickLog` and `TestClient_LifecycleLogs`, whose clients start no tickers today. The rule is the sink; a per-test judgement about which goroutines exist is what made this flake move between test names.
4. **`Close()` before the read** in the two tests that open a real client. `Close` stops both tickers, drains metrics synchronously, closes idle HTTP, and is idempotent, so the later `t.Cleanup(reclaim.ResetForTest)` is a no-op instead of a `Sleep` that spawns `go drainMetrics`. That is the goroutine-leak half of the fix.
5. **Assertions keep their subjects and their order** relative to what they measure: transport asserts stay before `Close`, log asserts move after it.

## Risks / Trade-offs

- [`Close` is production API called from a test in a way production does not] → It is the documented lifecycle call the reclaim Close hook makes; calling it early only ends the client sooner.
- [Deliverable 2 alone would not fix the reported race] → Accepted and expected: the writer is spawned inside `New` and cannot be joined. The sink is the load-bearing fix; stopping the client removes the leak the ticket also asks for.
- [A future test may reintroduce a raw `bytes.Buffer`] → The new spec leaf states the rule, and the usage packet names the helper.

## Migration Plan

Test-only. No operator key, no runtime behavior. Rollback is revert.
