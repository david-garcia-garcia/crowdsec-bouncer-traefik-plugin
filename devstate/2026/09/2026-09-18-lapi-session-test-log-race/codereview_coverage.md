# Test coverage

1. [judgement] Ticket job proven by repetition, not by an assertion — `pkg/lapi/zzz_logsink_test.go:12` — nothing fails if a later change hands a bare `bytes.Buffer` to a handler again; the proof is 12 consecutive clean Docker `-race` runs plus the CI `Race detector` job
   → Add `TestSyncLogSink_ConcurrentWriteAndRead` that hammers `Write` while reading `String`
   Status: skipped
   Argument: judgement. Such a test only catches "the mutex was deleted from the helper", which the race job already catches; it cannot catch the actual regression shape (a new test declaring its own buffer). This repo records house rules as a spec leaf plus a devdocs packet and has no filename-rule or helper-rule enforcement test, so adding one here would be a new idiom for no new coverage.

The assertions this change touches were all preserved: `TestClient_LifecycleLogs` (3 messages + 4 fields), `TestOpenStream_LiveMetricsMismatchSharesSilently` (client identity, `StreamFetches`, `hits`, 2 negative log asserts), `TestOpenStream_TLSOnlyAdoptsTransport` (client identity, adopted timeout, HTTP timeout, 2 positive log asserts), and both `captureTestStreamTickLog` level tables.
