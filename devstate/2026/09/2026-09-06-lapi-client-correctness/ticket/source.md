# LAPI stream poll races, HTTP transport panics/auth-retry body drop, and live scope fail-open

**IssueKey:** 2026-09-06-lapi-client-correctness  
**Component:** pkg/lapi  
**Severity:** bug (multiple defects, one change)

## Problem

`pkg/lapi` has several defects on the LAPI client paths (stream ticker, HTTP round-trip, live header-scope merge). They share one package and should land in one change with tests.

1. Overlapping `handleStreamTicker` goroutines race health fields, can duplicate stream GETs, and lease short-circuit can mask failures.
2. Transport error leaves a nil `*http.Response` then panics when the code still reads it (`client_http.go`).
3. 401 auth retry drops the POST body, which breaks alone-mode metrics POST.
4. Header-scope LAPI errors in `mergeLiveScope` are swallowed (fail-open).
5. `updateMaxFailure` / unhealthy recovery and stream JSON → cache apply are untested.

## Desired

- Serialize or join stream ticker work so health fields and stream GETs cannot overlap; lease short-circuit must not hide a failed poll.
- Never dereference a nil response after transport error; classify as LAPI failure.
- 401 retry must replay the original body (metrics POST in alone mode).
- Live header-scope query errors follow the same failure-action as IP live lookup; do not silently omit scopes.
- Tests for stream health transition, stream JSON apply, nil-response transport, POST retry, and live-scope error.

## Out of scope

OpenLive reclaim (covered). Duplicate metrics goroutine at New. `getToken` JSON special characters.

---

## Finding: stream-poll-concurrency

**Title:** Overlapping stream polls race health state and mask LAPI failures

Multiple `handleStreamTicker` goroutines can run at once on one `Client`. That violates the intended one-poller-per-session model, races stream-health fields without synchronization, can issue duplicate GET `/decisions/stream` calls (stealing CrowdSec cursor deltas), and lets a lease short-circuit report success while another poll is still failing—resetting `updateFailure` and keeping the stream “healthy” after a failed fetch.

**Evidence:**
- pkg/lapi/client.go:294-307 — `startTicker` launches `go work()` on every tick without waiting for the previous poll to finish.
- pkg/lapi/client.go:271-272 — `Wake()` also spawns `go c.handleStreamTicker()` while the stream ticker may already be running.
- pkg/lapi/client_stream.go:38-40 — `startStream` can add another concurrent poll (`go c.handleStreamTicker()` or synchronous call) before the ticker starts.
- pkg/lapi/client_stream.go:48-63 — `updateFailure`, `isCrowdsecStreamHealthy`, and `isCrowdsecStreamStartup` are read/written with no mutex or atomics.
- pkg/lapi/client_stream.go:66-72 — lease hit on key `updated` returns `nil` (success) without knowing whether an in-flight poll will fail.
- pkg/lapi/client_decisions.go:15-16 — `streamQuery()` reads `isCrowdsecStreamHealthy` / `isCrowdsecStreamStartup` while other goroutines mutate them.

**Desired:** Serialize stream polling per `Client` (mutex, single-flight, or “skip if poll in progress” that does not count as success). Only mark the stream healthy and reset `updateFailure` after a poll that actually reached LAPI and applied (or intentionally skipped with a valid lease from a completed poll). Add a test that overlaps `Wake()`/ticker polls and asserts failure accounting and a single stream GET under load.

---

## Finding: crowdsec-query-nil-response-on-transport-error

**Title:** Transport errors can panic crowdsecQuery via nil Response

When `http.Client.Do` returns a network/transport error, `crowdsecQuery` evaluates `isReverseProxyError(res.StatusCode)` even though `res` may be nil. That can panic the plugin process instead of returning a normal unreachable error to callers (stream poll, live lookup, metrics POST).

**Evidence:**
- pkg/lapi/client_http.go:88-90 — `if err != nil || isReverseProxyError(res.StatusCode)` reads `res.StatusCode` before checking `res != nil`.
- pkg/lapi/client_stream.go:89 — stream poll calls `crowdsecQuery` on transport failure path.
- pkg/lapi/client_decisions.go:84 — live decision fetch calls `crowdsecQuery`.
- pkg/lapi/client_metrics.go:215 — metrics POST calls `crowdsecQuery`.

**Desired:** Check `err != nil` first and return unreachable without touching `res`; only call `isReverseProxyError` when `res != nil`. Add a unit test with a custom `RoundTripper` that returns `(nil, err)` and assert no panic and a wrapped unreachable error.

---

## Finding: alone-mode-auth-retry-drops-post-body

**Title:** Alone-mode 401 retry reissues POST as GET without body

In alone (CAPI) mode, when LAPI returns 401, `crowdsecQuery` refreshes the token then retries with `crowdsecQuery(stringURL, nil)`. That turns the original POST into a GET with no body. Usage-metrics POSTs (and any other POST through this helper) silently fail or hit the wrong handler after token renewal.

**Evidence:**
- pkg/lapi/client_http.go:97-101 — on 401 in alone mode, retry always passes `nil` data.
- pkg/lapi/client_http.go:78-84 — `nil` data selects `http.MethodGet`.
- pkg/lapi/client_metrics.go:203-215 — `reportMetrics` POSTs JSON via `crowdsecQuery(..., data)`.

**Desired:** Retry with the same HTTP method and a fresh `bytes.NewReader(data)` (or equivalent) so POST semantics survive token refresh. Test: mock 401 once then 201, assert retry is POST with identical body.

---

## Finding: live-scope-query-error-fail-open

**Title:** Live header-scope LAPI errors are ignored instead of failing closed

After a successful IP live lookup, `mergeLiveScope` treats a failed header-scope LAPI query as a debug log and keeps the IP-only remediation. A transient LAPI error on the scope request therefore fail-opens traffic that may still match a header-scope ban on CrowdSec.

**Evidence:**
- pkg/lapi/client_live.go:17-25 — `handleNoStreamCache` only propagates errors from the IP `queryLiveDecisions` call.
- pkg/lapi/client_decisions.go:133-136 — `mergeLiveScope` on `headerErr != nil` logs debug and returns the prior `chosen` without error.
- pkg/bouncer/bouncer.go:201-207 — `applyLapiFailureAction` runs only when `LiveLookup` returns an error and the value is not active remediation.

**Desired:** Propagate scope query errors (or merge them into the returned error when IP was non-ban) so the bouncer can apply `lapiFailureAction`. At minimum, treat scope LAPI unreachable like IP LAPI unreachable in live mode. Add test: IP allows, scope query 500, assert error and no pass-through unless failure action is passthrough.

---

## Finding: stream-health-transition-untested

**Title:** Stream unhealthy threshold and recovery have no unit tests

`handleStreamTicker` drives whether cache misses fail-closed via `StreamHealthy()` in the bouncer, but the failure counter, `updateMaxFailure` threshold, unhealthy/healthy log transitions, and `startup=` query flag changes are untested.

**Evidence:**
- pkg/lapi/client_stream.go:48-63 — failure increments, unhealthy when `updateFailure >= updateMaxFailure` (default 0 → first failure), recovery clears counter.
- pkg/lapi/client_decisions.go:15-16 — `startup=` derives from health/startup flags set in `handleStreamTicker` / `handleStreamCache`.
- pkg/lapi/client_range_test.go:54-64 — `handleStreamCache` tested only for lease hit / range hydrate, not LAPI failure or health bits.

**Desired:** Table-driven httptest: (1) N failing stream responses mark unhealthy at the configured threshold; (2) success restores healthy and resets counter; (3) `updateMaxFailure: -1` stays healthy across failures; (4) optional assert on `streamQuery()` startup flag after recovery. Run polls synchronously (no ticker) to avoid the concurrency finding masking results.

---

## Finding: stream-fetch-decision-apply-untested

**Title:** Stream LAPI response → cache apply path is largely untested

The core stream value—fetching `/decisions/stream`, parsing `new`/`deleted`, writing IP/header/range slots, and updating active-decision metrics—is not covered by httptest. Only the lease-hit short-circuit (no HTTP) is tested.

**Evidence:**
- pkg/lapi/client_stream.go:88-131 — lease miss path: HTTP GET, unmarshal, loop `stream.New`/`stream.Deleted`, `storeStreamDecision` / `deleteStreamDecision`, `ApplyRangeBatch`.
- pkg/lapi/client_decisions.go:23-74 — scope switch for IP, header scopes, range skip on store/delete.
- pkg/lapi/client_range_test.go:54-64 — `TestHandleStreamCacheLeaseHitHydrates` only; no mock LAPI body.

**Desired:** httptest returning a non-empty stream body: assert cache keys/values/TTL, range index updates, `forgetActiveDecision` on delete, and active_decisions gauge keys after `handleStreamCache`. Include one header-scope decision when `decisionScopeHeaders` is configured.
