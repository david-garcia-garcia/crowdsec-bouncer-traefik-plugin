# Standards

1. [hard] Name for the scope — `pkg/lapi/client_stream_log_test.go:46` — `parsed` names `url.Parse`'s transform; the body only reads `parsed.Host` for the mock LAPI host
   → Rename to `serverURL` (or `lapiURL`) and use `.Host`
   Status: done
   Argument: renamed to `serverURL`.

2. [hard] Name for the scope — `pkg/lapi/client_stream_log_test.go:15` — `newStreamTickClient` is a test-only helper with no `Test`/`test` marker while the commandment requires test-only identifiers to say test (`newTestPlugin`) and sibling `newTestRangeClient` already does
   → Rename to `newTestStreamTickClient`
   Status: done
   Argument: renamed to `newTestStreamTickClient`.

3. [hard] Name for the scope — `pkg/lapi/client_stream_log_test.go:36` — `captureStreamTickLog` is a test-only helper with no `Test`/`test` marker
   → Rename to `captureTestStreamTickLog` (or match the `testStreamLAPI` prefix style)
   Status: done
   Argument: renamed to `captureTestStreamTickLog`.

4. [judgement] Consume before produce — `pkg/lapi/client_stream_log_test.go:85` — lease-hit path builds via `newStreamTickClient` though `newTestRangeClient` plus `lapiClient.log = log` already covers the same `handleStreamCache` setup in `client_range_test.go`
   → Reuse `newTestRangeClient` for `TestHandleStreamCacheAlreadyUpdatedIsDebug`; keep `newTestStreamTickClient` only where stream HTTP fields are required
   Status: skipped
   Argument: judgement; one helper keeps both tests on the same client shape.

5. [judgement] Duplicated Code — `pkg/lapi/client_stream_log_test.go:52-70` and `76-94` — both tests repeat the same table-driven INFO/DEBUG presence loop differing only in setup and `tickMsg`
   → Extract one table helper if a third tick assertion appears; two copies are acceptable for now
   Status: skipped
   Argument: judgement; two copies stay readable.
