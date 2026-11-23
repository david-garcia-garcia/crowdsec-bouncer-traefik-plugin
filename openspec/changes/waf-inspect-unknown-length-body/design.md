## Context

See proposal.md (Why). Today `pkg/wafhop/body.go` has the class `IsBodyUnreadable` (a body on HTTP/2 or later with `ContentLength < 0`) and the drop set `IsMethodWithBody` (POST, PUT, PATCH). AppSec (`pkg/appsec/query.go` `newAppsecBodyRequest`) and ModSec (`pkg/modsecurity/inspect.go` `Inspect`) each turn that class into their failure action, a gate skip while backing off, or a headers-only inspection. Every other body goes through `wafhop.ReadBody(req, limit, mode)`, which has no deadline. A stalled body there ends only at Traefik's entrypoint `readTimeout` (default 60 s), and the bouncer answers that with 400 `error:client-body-read` (`pkg/bouncer/bouncer_serve_waf.go`).

Measured facts this design relies on (`devstate` explore.md, Concepts › Reproduce; `knowledge/research/std_go_net-http_body-read-deadline/`, `knowledge/research/ext_traefik_plugins_body-read-deadline/`):

- `http.NewResponseController(w).SetReadDeadline(time.Now())`, called from a `time.AfterFunc`, cuts an in-flight body read on HTTP/1.1 and h2c (Go 1.25.6). The same program runs under Yaegi v0.16.1.
- On HTTP/1.1 the cut also cancels the request context, so today's `wafhop.IsClientGone` would read it as a disconnect. On HTTP/2 it is `os.ErrDeadlineExceeded` and the context stays live.
- `Body.Close()` cuts HTTP/2 but not HTTP/1.1 (#204 measurement).
- Traefik v3.7.19: every wrapper on the plugin writer chain implements `Unwrap`, and v3.7.17 fixed deadlines through wrapped writers. Whether the HTTP/1.1 cut works through Traefik is **inferred, not measured**. Implement measures it in the mock e2e.

Yaegi rules in this tree: no `select` on the request path, no goroutine of our own, no `atomic.Bool` / `atomic.Pointer` (`knowledge/research/ext_yaegi_interp_select-cases/`, `pkg/logger/debounce.go`).

Decisions already taken by the human (requirement.md, decisions 1–9) and by explore (explore.md Decisions and Open questions) are not argued again here. This file says how they are built.

## Goals / Non-Goals

**Goals:**

- One read path in `pkg/wafhop` that both legs call for every body they forward. The length signal only starts a deadline and never decides whether a body is read.
- A deadline that cuts the read on HTTP/1.1 and HTTP/2 with no goroutine and no `select`, and whose outcome is never mistaken for a client disconnect.
- A distinct answer the operator can see (400, `error:body-read-timeout`, WARN) that is neither a ban nor the failure action.

**Non-Goals:**

- A deadline on bodies with a declared `Content-Length` (requirement § Out of scope).
- Per-route deadline overrides, or classifying requests by Content-Type. Operators use `bypassAppsec` / `bypassModsec` / `bypass`.
- Inspecting past `appsecBodyLimit`, GET/HEAD bodies on AppSec, or any FailureAction / BackOffAction default or gate rule (decision 9).
- Measuring HTTP/3 (there is no h3 e2e in this repo).

## Decisions

### D1. One read path; the unreadable class is deleted

`wafhop.IsBodyUnreadable`, `wafhop.IsMethodWithBody`, AppSec `errUnreadableBody`, and both drop branches are removed together with their tests. AppSec `newAppsecBodyRequest` keeps two branches: `HasBody && isMethodWithForwardableBody` → `ReadBody` → POST, otherwise a headers-only GET. It no longer takes `Policy`, because nothing in the body path depends on the failure action any more (`newAppsecForwardRequest` drops it too). `isMethodWithForwardableBody` loses its "keep the two sets separate" comment. ModSec `Inspect` keeps `HasBody` → `ReadBody` for any method.

Rejected: keep `IsBodyUnreadable` and make its branch "read with a deadline". It keeps a protocol-specific class that the length check already covers, and it leaves HTTP/1.1 chunked bodies with no deadline.

### D2. Deadline inside `wafhop.ReadBody`

The signature becomes `ReadBody(httpReq, limit, mode, dl ReadDeadliner, timeout time.Duration)`, where `type ReadDeadliner interface{ SetReadDeadline(time.Time) error }` (`*http.ResponseController` satisfies it). In `bufferBody`, after the reuse check (a complete, untouched `bufferedBody` returns at once and starts nothing), and only when `httpReq.ContentLength < 0`:

```go
body := httpReq.Body // the body this call reads; captured for the fallback
timer := time.AfterFunc(timeout, func() {
	// The controller cuts HTTP/1.1 and HTTP/2; Close only cuts HTTP/2.
	if dl == nil || dl.SetReadDeadline(time.Now()) != nil {
		_ = body.Close()
	}
})
_, err := buf.ReadFrom(reader)
fired := !timer.Stop()
```

`ReadBody` checks `fired` first and returns `ErrBodyReadTimeout` whatever `err` is. Then it checks `IsClientGone` (unchanged), then `ErrClientBodyRead`. The success path never calls `SetReadDeadline`. Clearing the deadline would remove Traefik's own `readTimeout` for the rest of an oversize body. A body with a declared length starts no timer.

Implement chooses how the `fired` result travels from `bufferBody` to `ReadBody` (a return value is enough). The doc comment says which call owns the cut.

Rejected:
- Reading in a goroutine and giving up (upstream #407): the read has no owner, and it adds our own goroutine on the request path under Yaegi.
- `context.WithTimeout`: a context does not unblock `Body.Read`.
- `Body.Close` alone: it does not cut HTTP/1.1.
- `SetReadDeadline(now + d)` before the read and clearing it after: clearing drops Traefik's `readTimeout`.
- Classifying by error type: on HTTP/1.1 the cut looks like a disconnect (measured).

### D3. Sentinel and limit contract

- `wafhop.ErrBodyReadTimeout = errors.New("wafhop:bodyReadTimeout")`, documented next to `ErrClientBodyRead`. It does not wrap it and is not wrapped by it, so `errors.Is` keeps the two apart. `appsec.ErrBodyReadTimeout` aliases it the same way `appsec.ErrClientBodyRead` aliases its sentinel.
- `ReadBody` / `bufferBody` lose the `limit <= 0` (no cap) branches. A non-positive limit is a caller bug, and the doc comment says so. The `math.MaxInt64` guard stays. Both callers always pass a value of at least 1 (deviation row by explore).

### D4. The legs receive the per-request control (deviation, by explore)

- `appsec.Client.Query(req clientrequest.Request, pol Policy, dl wafhop.ReadDeadliner)`.
- `modsecurity.Client.Inspect(req *http.Request, dl wafhop.ReadDeadliner)` replaces `failureAction string`, whose only use was the removed drop branch.
- `serveAppSec` and `serveModSec` each pass `http.NewResponseController(rw)`: the bouncer is the only owner of `rw`, and building the controller costs nothing, so both sides stay symmetric. Tests pass `nil` (falls back to `Body.Close`) or a stub.
- Migration: `Query` has 1 production and 69 test calls, `Inspect` 1 production and 5 test calls (explore.md, Call sites). The change is mechanical.

Rejected: a field on `clientrequest.Request` (that type is the request plus the chosen address), on `appsec.Policy` (per-route config, not per-request I/O), or on the request context (hidden plumbing). Also rejected: a `ReadPolicy{Limit, Mode, Timeout}` value type. There are only three scalars and two callers, so separate parameters keep the migration mechanical.

### D5. Config, per-leg keys, identity

- `configuration.Config`: `AppsecBodyReadTimeoutSeconds int64 \`json:"appsecBodyReadTimeoutSeconds,omitempty"\`` and `ModsecBodyReadTimeoutSeconds int64 \`json:"modsecBodyReadTimeoutSeconds,omitempty"\``, each placed alphabetically by tag. `DefaultBodyReadTimeoutSeconds = 30` is used by `New()` and `CreateConfig` for both. Both go in `requiredInt1`, next to the `*HTTPTimeoutSeconds` siblings.
- `DefaultAppsecBodyLimit = 10485760` becomes a named constant. `EffectiveAppsecBodyLimit(limit int64) int64` goes next to `EffectiveFailureAction`. `AppsecBodyLimit` leaves `requiredInt0`, and the duplicate `< 0` check is deleted.
- `appsec.Prepare` writes the effective body limit back onto the snapshot (inside the `AppsecEnabled` block), so `identityFrom` hashes 0, a negative value, and 10485760 the same. `appsec.New` also stores the limit through `EffectiveAppsecBodyLimit`, so a Client built without `Prepare` (tests, `NewTestClient`) never holds a non-positive cap.
- Inside each package the stored field drops the leg prefix: `bodyReadTimeout time.Duration` on each `Client`, and `BodyReadTimeoutSeconds` (JSON `bodyReadTimeoutSeconds`) on the AppSec `identity` and the ModSec `ownership`.
- The bouncer needs the timeout for the WARN attr `timeoutSeconds`. Each Client exposes `BodyReadTimeoutSeconds() int64`. The bouncer already holds the loaded Client at the call site.

### D6. The bouncer answer

- `pkg/bouncer/remediation_header.go`: `headerReasonBodyReadTimeout = "body-read-timeout"`.
- `pkg/bouncer/bouncer_serve_waf.go`: `handleBodyReadTimeoutServeHTTP(rw, req, leg, timeoutSeconds)` sets `error:body-read-timeout`, writes `http.Error(rw, StatusText(400), 400)`, and logs the leg's WARN through `logger.Debounced(b.log, slog.LevelWarn, 5*time.Second, msg, "ip", req.IPAddrString(), "method", req.Method, "host", req.Host, "path", req.URL.Path, "timeoutSeconds", timeoutSeconds)`. The two message constants are the spec text (`core_plugin_middleware_bouncer` "Body read deadline is logged at WARN once per window per leg"). It sits next to the two existing client-body answers.
- `answerAppsecQueryError` and `serveModSec` each get one `errors.Is(err, wafhop.ErrBodyReadTimeout)` case, placed before their `ErrClientDisconnected` case. The order does not matter for correctness, but keeping it the same in both places is easier to read. No ban, no `recordDropped`, no failure action. The gate is untouched because the read happens before admission on both legs.
- The WARN lives in the bouncer, not in `pkg/wafhop`: the bouncer owns the client address (`clientrequest.Request`, from `pkg/ip.GetRemoteIP`) and knows the leg. `wafhop` has no request identity.

Rejected:
- #204's ban path (`ban:appsec-body-timeout`, `plugin:appsec_body_timeout`): master already answers every "client body did not arrive whole" case with 400 and no ban, including Traefik's own `readTimeout`. A ban would count a slow client as a WAF drop and need new origins on two legs.
- HTTP 408: RFC 9110 §15.5.9 invites the client to retry into the same block.
- Reusing `client-body-read`: access logs and e2e could then not tell the plugin deadline from Traefik's.

### D7. Two legs on one request

There is no shared deadline object. AppSec runs first. A body it buffered whole is reused by ModSec, which starts no timer and still applies its own limit (413). If AppSec stopped at its limit, ModSec reads the rest through the restored body (memory first, then the network) and starts its own timer for that read only. With default limits (10 MiB ≥ 8 MiB) ModSec never reaches the network. The worst-case wait is AppSec timeout + ModSec timeout, and only when `modsecBodyLimit > appsecBodyLimit`. The docs say so next to the keys.

### D8. Tests and e2e

- `pkg/wafhop`: a never-ending reader with a nil controller times out through `Close`; a stub controller is called with a time at or before now; `fired` wins over a `context.Canceled` error; a declared-length slow body is not cut; reuse starts no timer; a real `httptest` HTTP/1.1 chunked server and an HTTP/2 server (TLS `EnableHTTP2`, since h2c is not vendored) are cut by `http.NewResponseController`.
- `pkg/appsec` and `pkg/modsecurity`: unknown-length POST/PUT/PATCH/DELETE (`ProtoMajor 2`, `ContentLength -1`) reaches the WAF with the bytes under every failure action; an empty such body reaches the WAF and is allowed; a stalled one returns `ErrBodyReadTimeout` and the WAF is not called; AppSec GET with such a body stays headers-only; 0 and -1 limits cap at 10 MiB; identity tests for the new knob and for 0 vs omitted.
- `pkg/bouncer`: 400 + header + no drop + `next` not called for each leg and each failure action; WARN debounced with its attrs (house log sink, `knowledge/devdocs/std_go_test_log-sink.md`); `bypassAppsec` / `bypassModsec` skip the read.
- Yaegi: a `pkg/yaegitest` program runs the deadline path (pattern `pkg/bouncer/zzz_yaegi_leg_binding_test.go`).
- Mock e2e (`tests/e2e/mock/scenarios/appsec`) and real e2e (`tests/e2e/real/modsec.Tests.ps1`): see tasks groups 6 and 7. The measured HTTP/1.1 behaviour through Traefik v3.7.19 is recorded on explore.md (row "Does `http.ResponseController.SetReadDeadline` cut…", `By: implement`).

## Risks / Trade-offs

- [Streaming request bodies (gRPC client or bidirectional streaming, Connect streaming, long uploads without `Content-Length`) are blocked after 30 s on routes that are not excluded] → a how-to page with `bypassAppsec` / `bypassModsec` recipes and the trade-off. The WARN names the key and the escape hatch, and the header tells the plugin deadline apart from Traefik's.
- [A slow but finite upload without `Content-Length` that cannot deliver `min(body, limit)` within 30 s is blocked (about 2.8 Mbit/s for 10 MiB)] → the key is configurable, and the docs give the arithmetic.
- [`appsecBodyLimit: 0` operators go from unlimited to 10 MiB without being told] → upgrade note in `docs/configuration.md`, and the PR marks it BREAKING.
- [The HTTP/1.1 cut may not reach the connection through Traefik's writer chain under Yaegi] → the `Body.Close` fallback still cuts HTTP/2. On HTTP/1.1 the timer flag still blocks the request once the read ends (the client finishes or gives up, or Traefik `readTimeout`). Implement measures this and writes down what it found. The spec scenario for HTTP/1.1 states its precondition (control available).
- [HTTP/3 is not measured] → Traefik sets read deadlines through `ResponseController` on h3 itself (inference). The docs say "expected", not "measured".
- [Every AppSec and ModSec Client is re-keyed once on upgrade] → as with any identity change: a new Client on the first Open after the upgrade. No persistent storage.
- [The timer fires just as the last byte arrives] → the request is blocked although the body completed. That is acceptable at a 30 s boundary, and it keeps one unambiguous classifier.
- [Two ADDED requirements carry descriptions over 500 characters (`openspec validate` warning)] → both are existing requirement texts moved unchanged under a new name (REMOVED + ADDED, because OpenSpec refuses to drop scenarios in a MODIFIED block). Splitting them is a separate change.
- [The parallel run `2026-11-23-backoff-action-per-leg` edits the same AppSec/ModSec spec leaves and gate code] → no default or gate rule changes here. Whichever change merges second rebases its deltas.

## Migration Plan

No persistent storage. Rollback is deploying the previous plugin version, which brings the old drop / headers-only behaviour back. Operators who set `appsecBodyLimit: 0` and need more than 10 MiB set an explicit positive value before upgrading. Operators who run streaming request bodies add a `bypassAppsec` / `bypassModsec` (or `bypass`) rule for those routes before upgrading.

## Open Questions

- Does `http.ResponseController` reach Traefik v3.7.19's connection for HTTP/1.1 under Yaegi? Implement measures it. This does not change the specs (the request is blocked either way), only how fast an HTTP/1.1 stall is answered and the doc wording. Row: explore.md, open question on `SetReadDeadline` through Traefik.
