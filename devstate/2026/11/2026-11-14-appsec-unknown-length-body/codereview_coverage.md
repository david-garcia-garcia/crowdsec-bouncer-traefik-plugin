# Test coverage

1. [judgement] Happy path only — `pkg/appsec/query.go:286` — the armed-timer arm where a body of unknown length fails with a client-gone error before the deadline (`Stop()` true, falls through to `isClientGoneBodyReadErr` at line 298) has no test; every `ErrClientDisconnected` test builds its request with `newReadablePostWithFailingBody` (`ContentLength = 100`), so no timer is armed, and a change that reported any read error on an unknown-length body as `ErrBodyReadTimeout` (ban instead of a silent stop) would stay green
   Quote:
   ```
   query.go:286  if deadlineTimer != nil && !deadlineTimer.Stop() { ... return nil, ErrBodyReadTimeout }
   query.go:298  if isClientGoneBodyReadErr(err) { return nil, ErrClientDisconnected }
   test: (none) — zzz_test_helpers.go newReadablePostWithFailingBody sets req.ContentLength = 100
   ```
   Fix: Add a case to `Test_appsecQuery_clientDisconnected` that uses `newUnknownLengthRequest(http.MethodPost, failingBody{err: context.Canceled})` and asserts `ErrClientDisconnected`, not `ErrBodyReadTimeout`, with zero AppSec hits
   Status: skipped
   Argument: judgement; not applied unattended. The fired-timer-first ordering is covered by `TestBodyReadTimeout_FiredTimerWinsOverReadError`; an unknown-length disconnect-before-deadline case is a worthwhile follow-up test.
