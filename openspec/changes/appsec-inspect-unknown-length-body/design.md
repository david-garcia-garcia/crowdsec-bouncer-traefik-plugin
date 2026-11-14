## Context

See proposal.md Why. Today `newAppsecBodyRequest` (`pkg/appsec/query.go`) has three branches: "unreadable" (`isBodyUnreadable`: HTTP/2+ and `ContentLength < 0`) → drop via `resultForFailureActionErr` for POST/PUT/PATCH (`isMethodWithBody`) or headers-only GET; readable body on POST/PUT/PATCH/DELETE (`isMethodWithForwardableBody`) → `io.ReadAll` (capped with `io.LimitReader` only when `appsecBodyLimit > 0`), `io.MultiReader` restore; everything else → headers-only GET. No read deadline exists; a stalled body is bounded only by Traefik's entrypoint `readTimeout`.

Measured on Go 1.25.6 (`knowledge/research/std_go_net-http_body-read-deadline/`): `http.ResponseController.SetReadDeadline(time.Now())` from a timer cuts an in-flight body read on HTTP/1.1 and HTTP/2 and the read returns a wrapped `os.ErrDeadlineExceeded`; `Body.Close()` cuts HTTP/2 but **not** HTTP/1.1 (`body.Close` waits on the mutex `Read` holds); reading in a goroutine and giving up (upstream #407) holds the HTTP/1.1 response until the client ends the body. Yaegi v0.16.1 rules in this tree: no `select` on the request path (`knowledge/research/ext_yaegi_interp_select-cases/`), `atomic.Value` instead of `atomic.Pointer[T]` / `atomic.Bool` (`pkg/appsec/client.go`, `pkg/lapi/client.go`), `time.AfterFunc` is already the chosen timer (`pkg/reclaim/default.go`).

Decisions already taken by the human (`requirement.md` Decisions 1–8) and by explore (`explore.md` Decisions and Open questions) are not re-argued here; this file says how they are built.

## Goals / Non-Goals

**Goals:**

- One body read path in `newAppsecBodyRequest`; the length signal only arms a deadline.
- A deadline that cuts the read on HTTP/1.1 and HTTP/2 without a goroutine or `select` of our own, and whose outcome cannot be misread as a client disconnect.
- A distinct, operator-visible outcome (header reason, metrics origin, WARN) that is not `appsec-failure`.

**Non-Goals:**

- A deadline on bodies with a declared `Content-Length` (explore Open question 1).
- Per-route deadline overrides or Content-Type classification (operators use `bypassAppsec`).
- Inspecting past `appsecBodyLimit`, GET/HEAD bodies, `appsecResponseBodyLimit`, `appsecHttpTimeoutSeconds` semantics.
- HTTP/3 measurement (no h3 e2e in this repo).

## Decisions

### D1. Unify the read path; delete the unreadable class

`newAppsecBodyRequest` keeps two branches: forwardable method with a non-`NoBody` body → capped read; otherwise headers-only GET. `isBodyUnreadable` and `isMethodWithBody` are deleted with their tests. `isMethodWithForwardableBody` stays the only method predicate. A new predicate `isBodyLengthUnknown(httpReq)` (`ContentLength < 0`) gates only the deadline. `newAppsecBodyRequest` no longer takes `Policy`: nothing in the body path depends on the failure action any more (`newAppsecForwardRequest` drops it too).

Alternative: keep `isBodyUnreadable` and change its branch to "read with deadline" — rejected, it keeps a protocol-specific class that the length predicate already covers and would leave HTTP/1.1 chunked without a deadline.

### D2. Deadline mechanism: timer → `SetReadDeadline(now)`, fallback `Body.Close`

Inside the read helper (`copyClientBodyForAppsecAndRestoreForOrigin`), when the length is unknown:

```go
timer := time.AfterFunc(c.bodyReadTimeout(), func() {
	// Cut the in-flight read. The controller reaches HTTP/1.1 and HTTP/2; Close only HTTP/2.
	if responseController == nil || responseController.SetReadDeadline(time.Now()) != nil {
		_ = httpReq.Body.Close()
	}
})
bodyBytes, err := io.ReadAll(io.TeeReader(io.LimitReader(httpReq.Body, c.appsecBodyLimit), &bodyBuffer))
deadlineFired := !timer.Stop()
if deadlineFired {
	return nil, ErrBodyReadTimeout // before isClientGoneBodyReadErr, whatever err is
}
```

- `deadlineFired` is the only classifier of the outcome. The cut read's error (`i/o timeout`, `body closed by handler`, or nil when the timer raced the last byte) is never inspected for this decision, so `isClientGoneBodyReadErr` stays unchanged and cannot turn a deadline into a silent disconnect.
- The success path never touches the read deadline. Clearing it (`SetReadDeadline(time.Time{})`) would drop Traefik's own `readTimeout` timer for the remainder of an oversize body (HTTP/2 `st.readDeadline = nil`). Rejected.
- Known-length bodies skip the timer entirely.
- Yaegi: only native `time.AfterFunc`, `Timer.Stop`, `net/http` calls; the callback closure is the same shape `pkg/reclaim` already runs under Yaegi.

Alternatives: read in a goroutine and stop waiting (upstream #407) — holds the HTTP/1.1 response, leaves an unowned read; `context.WithTimeout` — a context does not unblock `Body.Read`; `Body.Close` alone — does not cut HTTP/1.1 (measured).

### D3. `Query` receives the per-request controller (deviation, by explore)

Signature becomes `Query(req clientrequest.Request, pol Policy, responseController *http.ResponseController)`. The bouncer builds it with `http.NewResponseController(rw)` in `applyAppsecServeHTTP` (sole owner of `rw`) and passes it down to the read helper. `nil` is allowed and means "Body.Close only" (tests that have no writer). It is a separate parameter, not a field on `clientrequest.Request` (that type is the request + chosen address + scheme cluster) and not on `Policy` (per-route config).

Migration: 1 production call (`pkg/bouncer/bouncer.go`), 43 test calls in `pkg/appsec` (enumerated in `explore.md` Call sites); tests that do not exercise the deadline pass `nil`.

### D4. Outcome: `ErrBodyReadTimeout`, served as its own ban

- `pkg/appsec`: `var ErrBodyReadTimeout = errors.New("appsecQuery:bodyReadTimeout")`, documented like `ErrClientDisconnected`. `Query` returns it straight from `newAppsecForwardRequest`, so the listener is never called and `resultForFailureAction` is never consulted.
- The WARN is emitted in `pkg/appsec` at the point the sentinel is produced (the owner of the knob and of the read), through `logger.Debounced(c.log, slog.LevelWarn, 5*time.Second, msgBodyReadTimeout, "ip", req.IPAddrString(), "method", req.Method, "host", req.Host, "path", req.URL.Path, "timeoutSeconds", c.bodyReadTimeoutSeconds)`. Message text is fixed in the spec (`core_plugin_appsec_body-read-timeout`). Client address comes from `clientrequest.Request` (owner: `pkg/ip.GetRemoteIP`); do not re-derive it.
- `pkg/bouncer`: in `applyAppsecServeHTTP`, after the `ErrClientDisconnected` branch: `if errors.Is(err, appsec.ErrBodyReadTimeout) { b.warnCaptchaSuperseded(req, match); b.handleBanServeHTTP(rw, req, configuration.ReasonAPPSEC, headerReasonAppsecBodyTimeout, lapi.OriginPluginAppsecBodyTimeout); return true }`. It never reaches the generic Debug + `appsec-failure` branch.
- `headerReasonAppsecBodyTimeout = "appsec-body-timeout"` in `pkg/bouncer/remediation_header.go`; the body-timeout ban passes it straight to `handleBanServeHTTP`, so `headerReasonFromOrigin` does not map the new origin (same as `OriginPluginTechCacheFail`).
- `OriginPluginAppsecBodyTimeout = "plugin:appsec_body_timeout"` in `pkg/lapi/client_metrics.go` next to `OriginPluginAppsecFailure`.

Alternatives: HTTP 408 — RFC 9110 §15.5.9 invites the client to retry into the same block and skips the operator's status code, template, header, and metrics; reuse `appsec-failure` — Decision 7 reserves it for "AppSec failed".

### D5. Config: new key and body-limit default

- `configuration.Config` gains `AppsecBodyReadTimeoutSeconds int64 \`json:"appsecBodyReadTimeoutSeconds,omitempty"\`` right after `AppsecBodyLimit` (alphabetical by tag). `New()` defaults it to `DefaultAppsecBodyReadTimeoutSeconds = 30`. `ValidateParams` adds it to `requiredInt1`.
- `DefaultAppsecBodyLimit = 10485760` becomes a named constant used by `New()`. `EffectiveAppsecBodyLimit(limit int64) int64` (next to `EffectiveFailureAction`, same pattern) returns the default for `<= 0`. `appsec.Prepare` writes the effective value back onto the snapshot, so `identityFrom` and `appsec.New` see it; `appsec.New` also stores `EffectiveAppsecBodyLimit(config.AppsecBodyLimit)` so a Client built without `Prepare` can never hold a non-positive cap (`io.LimitReader` with `N <= 0` is immediate EOF: `knowledge/research/std_go_io_limit-reader/`). `NewTestClient` uses both default constants.
- `AppsecBodyLimit` leaves `requiredInt0`; the duplicate `< 0` check after `NewActionSet` is deleted.
- Inside `pkg/appsec` the stored field drops the domain prefix: `bodyReadTimeoutSeconds` on `Client`, `BodyReadTimeoutSeconds` on `identity` (JSON `bodyReadTimeoutSeconds`).

### D6. Tests and e2e

- Unit (`pkg/appsec`): rewrite the drop / unreadable tests into inspection tests (HTTP/2-shaped `ContentLength -1` POST/PUT/PATCH/DELETE → AppSec POST with the bytes; empty body → AppSec queried, allow); passthrough no longer yields a headers-only GET; deadline fires on a never-ending body for each failure action → `ErrBodyReadTimeout`, listener not called; a real `httptest.Server` (HTTP/1.1 chunked) and an h2c server prove `SetReadDeadline` cuts the read within the deadline; a fired timer wins over a client-gone-looking error; zero/negative limit caps at 10 MiB; identity changes with the new knob and is equal for `0` vs omitted limit.
- Unit (`pkg/bouncer`): body-timeout → status, header `ban:appsec-body-timeout`, origin `plugin:appsec_body_timeout`, captcha rule superseded, `bypassAppsec` skips the read.
- Yaegi (`pkg/yaegitest`): run the deadline path under the yaegi v0.16.1 binary (explore Open question 3).
- Mock e2e (`tests/e2e/mock/scenarios/appsec`): see tasks group 6.

## Risks / Trade-offs

- [Streaming request bodies (gRPC client/bidi streaming, Connect streaming, long uploads without `Content-Length`) are blocked after 30 s on routes not excluded] → README section with `bypassAppsec` recipes; WARN names the key and the escape hatch; header and metrics origin make the cause visible.
- [Slow legitimate upload without `Content-Length` that does not deliver `min(body, 10 MiB)` within 30 s is blocked (≈2.8 Mbit/s for the full 10 MiB)] → configurable key; README states the arithmetic.
- [`appsecBodyLimit: 0` operators silently go from unlimited to 10 MiB] → README upgrade note; PR description calls it out as breaking.
- [Traefik's `ResponseWriter` wrappers may not expose `SetReadDeadline` through `Unwrap` under Yaegi] → fallback `Body.Close` cuts HTTP/2; the timer flag still classifies the block on HTTP/1.1 once the read ends (client end or Traefik `readTimeout`). Implement measures this with the mock e2e on the real Traefik binary and records the result on explore Open question 3 and in the README.
- [HTTP/3 behaviour not measured] → `Body.Close` assumed to cut a quic stream; stated as unmeasured in README/PR.
- [Every AppSec Client is re-keyed once on upgrade (new identity field)] → same as any identity change: a new Client on first Open after upgrade; no persistent storage involved.
- [Timer fires right as the last byte arrives] → request is blocked although the body completed; acceptable at a 30 s boundary and keeps one unambiguous classifier.

## Migration Plan

No persistent storage. Rollback = deploy the previous plugin version; the old behaviour (drop / headers-only) returns. Operators who set `appsecBodyLimit: 0` and need more than 10 MiB set an explicit positive value before upgrading.

## Open Questions

- Does `http.ResponseController` reach Traefik's underlying writer under Yaegi (HTTP/1.1 cut)? Deferred to implement's measurement; it does not change the spec (the request is blocked either way) — only how fast an HTTP/1.1 stall is answered. Row: `explore.md` Open questions 3.
