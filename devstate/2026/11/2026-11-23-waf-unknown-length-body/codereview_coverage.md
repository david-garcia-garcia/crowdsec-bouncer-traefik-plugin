# Test coverage

1. [hard] Edge case untested — `pkg/bouncer/bouncer_serve_modsec.go:32` — the ModSec leg's HTTP/1.1 deadline cut through `http.NewResponseController(rw)` has no test that fails on revert: every ModSec stall test uses an HTTP/2 shape or a recorder, so the `Body.Close` fallback ends the read, and passing `nil` here keeps them all green while an HTTP/1.1 chunked stall would only end when the body ends or at Traefik's `readTimeout`
   Fix: Add a `pkg/bouncer` test that runs an `httptest` HTTP/1.1 server whose handler calls `continueAfterLAPIForTest` with only the ModSec leg bound (`modsecBodyReadTimeoutSeconds` 1), sends a chunked body that stalls 5 s, and asserts 400 `error:body-read-timeout` well before the body ends
   Status: done
   Argument: Added `TestServeHTTP_bodyReadTimeoutCutsHTTP1Chunked` in `pkg/bouncer/zzz_body_read_timeout_test.go`: a real HTTP/1.1 chunked body that stalls is answered 400 `error:body-read-timeout` in about 1 s on each leg; verified it fails (10 s) when `serveModSec` passes `nil` instead of the controller.
   Quote:
   ```
   production: blocked, err := client.Inspect(req.Request, http.NewResponseController(rw))
   tests grepped: pkg/bouncer/zzz_body_read_timeout_test.go assertStalledBodyIs400 (httptest.NewRecorder + HTTP/2 stallingTestBody, cut by Close)
                  pkg/modsecurity/zzz_inspect_test.go TestInspect_stalledUnknownLengthBodyTimesOut (Inspect(req, nil), HTTP/2)
                  tests/e2e/real/modsec.Tests.ps1 "400 error:body-read-timeout at the deadline" (h2c only; Close also cuts HTTP/2)
   HTTP/1.1 stall through the leg: AppSec only (tests/e2e/mock/scenarios/appsec/run.sh h1-stall, 1500..3500 ms); ModSec (none)
   ```
