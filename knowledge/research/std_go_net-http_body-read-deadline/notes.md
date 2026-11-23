# Server request body read deadline

How a Go `net/http` handler can stop an in-flight read of the inbound request body at a deadline, per protocol, and what error that read returns.

Fetched: 2026-11-14. Revised: 2026-11-23 (ported from the superseded PR #204 branch; 2026-11-23 probe added). Pin: Go 1.25.6 (`golang/go@go1.25.6`, local `C:\Program Files\Go\src\net\http`). Permalinks: `https://github.com/golang/go/blob/go1.25.6/src/net/http/<file>`.

## Which abort works on which protocol

| mechanism | HTTP/1.1 | HTTP/2 |
|-----------|----------|--------|
| `r.Body.Close()` from another goroutine (timer) | Does **not** unblock the read. `Close` waits on the same `b.mu` that `Read` holds, then drains. | Unblocks at once. Read returns `body closed by handler`. |
| `http.NewResponseController(w).SetReadDeadline(t)` | Works. Sets the `net.Conn` read deadline. | Works. Arms the per-stream timer; a past `t` fires at once. |
| `http.Server.ReadTimeout` | Works. Whole-request deadline on the `net.Conn`. | Works. Per-stream timer armed after headers. |
| Read in a goroutine, handler returns without cancelling | Response is held until the client ends its body (background `Read` holds the body mutex). | Stream closes when the handler returns; background read ends then. |

Owners:

- HTTP/1 `body.Read` holds `b.mu` for the whole read; `body.Close` takes the same lock, then drains up to `maxPostHandlerReadBytes` (`io.CopyN(io.Discard, …)`). (`golang/go@go1.25.6:src/net/http/transfer.go` L831, L971-1010; `.sources/transfer.go.md`)
- HTTP/2 `http2requestBody.Close` calls `pipe.BreakWithError(http2errClosedBody)`; `http2errClosedBody` is `"body closed by handler"`. (`src/net/http/h2_bundle.go` L6508, L4017; `.sources/h2_bundle.go.md`)
- HTTP/1 `response.SetReadDeadline` is `c.conn.rwc.SetReadDeadline(deadline)`; ReadTimeout sets the same conn deadline after headers. (`src/net/http/server.go` L499-500, L1025-1026, L1085-1086; `.sources/server.go.md`)
- HTTP/2 `SetReadDeadline` in the past calls `st.onReadTimeout()` immediately; otherwise it arms or resets `st.readDeadline`. ReadTimeout arms the same per-stream timer after headers. (`src/net/http/h2_bundle.go` L6778-6802, L6072-6074)
- HTTP/2 `closeStream` calls `p.CloseWithError(err)` on the stream body. (`src/net/http/h2_bundle.go` L5668, L5700)
- Measured behaviour of every row: local probe. (authority: inference — `.sources/local-go1256-body-deadline-probe.md`)

## Error the read returns

Deadline expiry (ReadTimeout or `SetReadDeadline`) surfaces as a wrapped `os.ErrDeadlineExceeded`, text contains `i/o timeout`, on both protocols. It is **not** `context.DeadlineExceeded` and **not** `context.Canceled`. Classify with `errors.Is(err, os.ErrDeadlineExceeded)`.

- HTTP/2: `onReadTimeout` closes the body with `fmt.Errorf("%w", os.ErrDeadlineExceeded)` (L5951-5957). Message: `i/o timeout`.
- HTTP/1: the error comes from the `net.Conn` read: `read tcp …: i/o timeout`. Probe: `errors.Is(err, os.ErrDeadlineExceeded)` = true. (authority: inference — probe; the net package wrapping was not re-read here)

Other abort errors seen in the probe (none match `os.ErrDeadlineExceeded` or a context error):

- HTTP/2 `Body.Close` from a timer: `body closed by handler`.
- HTTP/2 background read after the handler returned: `stream error: stream ID 1; NO_ERROR`.
- HTTP/1 `Body.Close` or goroutine shape: the read ends with nil error when the client finishes the body; no deadline is enforced.

## ReadTimeout interaction

- `Server.ReadTimeout` is "the maximum duration for reading the entire request, including the body. A zero or negative value means there will be no timeout." (`src/net/http/server.go` L3015-3023)
- `ResponseController.SetReadDeadline`: "Setting the read deadline after it has been exceeded will not extend it." A zero value means no deadline. (`src/net/http/responsecontroller.go` L80-84; `.sources/responsecontroller.go.md`)
- HTTP/2: a zero deadline sets `st.readDeadline = nil`, so it also drops the ReadTimeout-derived per-stream timer. If that timer already fired, `Stop()` returns false and the call changes nothing. (`h2_bundle.go` L6787-6794)
- HTTP/1: ReadTimeout and `SetReadDeadline` write the same `net.Conn` deadline; the last call wins, so a later or zero deadline replaces the ReadTimeout one. (`server.go` L499-500, L1085-1086; inference from code)
- Probe: ReadTimeout 5 s plus a 300 ms ResponseController deadline on HTTP/2 → read ended at 300 ms with `os.ErrDeadlineExceeded`. A shorter handler deadline therefore wins on HTTP/2. (authority: inference — probe)

## ResponseController and wrappers

`SetReadDeadline` walks `Unwrap() ResponseWriter` until a writer implements `SetReadDeadline(time.Time) error`; otherwise it returns an error wrapping `http.ErrNotSupported`. (`src/net/http/responsecontroller.go` L23-24, L85-97, L145-146) Handle that error: when unsupported, no deadline was set.

## Unknown-length body side note

An HTTP/2 POST whose client body is empty and has no Content-Length reaches the handler with `ContentLength == -1` and `Body != http.NoBody`; `io.ReadAll` returns at once with 0 bytes and nil error. (authority: inference — probe, restic `?create=true` shape)

## Measured on the superseded PR #204 branch (2026-11-14)

Test files below live on branch `2026-11-14-appsec-unknown-length-body` (PR #204), not on master.

- Yaegi v0.16.1, plain `net/http` server: a timer calling `ResponseController.SetReadDeadline(time.Now())` cuts an HTTP/1.1 chunked read at the deadline. (authority: inference — `pkg/appsec/zzz_yaegi_body_read_timeout_test.go` on that branch)
- HTTP/2 over TLS (`httptest` `EnableHTTP2`): same cut at the deadline. (authority: inference — `pkg/appsec/zzz_body_read_timeout_test.go` on that branch)
- **Traefik v3.7.11 only**: binary with the plugin loaded under Yaegi (mock e2e, access log on and off). HTTP/2 without Content-Length was answered at the deadline; an HTTP/1.1 chunked read was **not** cut: the handler's read returned only when the client ended or abandoned its body. The `Body.Close` fallback cannot cut HTTP/1.1. Which wrapper stopped `Unwrap` was not determined. (authority: inference — `tests/e2e/mock/scenarios/appsec/run.sh` on that branch and probe runs) For Traefik v3.7.19 the writer chain was re-read: see `../ext_traefik_plugins_body-read-deadline/`. Not re-measured on v3.7.19.

## Measured 2026-11-23 (Go 1.25.6, plain net/http, and Yaegi v0.16.1)

Probe shape: the handler arms `time.AfterFunc(300ms)` that calls `http.NewResponseController(w).SetReadDeadline(time.Now())` (falls back to `r.Body.Close()` on error), reads `io.ReadAll(io.LimitReader(r.Body, 1 MiB))`, computes `fired := !timer.Stop()`, then writes 400. Client body = `io.Pipe` writing `"ab"` and never ending (closed after 3 s). (authority: inference — `.sources/local-go1256-body-deadline-probe-2026-11-23.md`)

| case | read result | `fired` | `r.Context().Err()` | `IsClientGone` copy | client |
|------|-------------|---------|---------------------|---------------------|--------|
| HTTP/1.1 chunked, never-ending | 2 bytes, `read tcp …: i/o timeout` (`os.ErrDeadlineExceeded`) at 300 ms | true | `context.Canceled` | **true** | 400 at 300 ms |
| h2c, no Content-Length, never-ending | 2 bytes, `i/o timeout` (`os.ErrDeadlineExceeded`) at 300 ms | true | nil | false | 400 at 300 ms |
| h2c POST, empty body, no Content-Length | `CL=-1`, `Body != http.NoBody`, 0 bytes, nil error, 0 s | false | nil | n/a | 400 |
| HTTP/1.1 chunked under a `yaegi` v0.16.1 binary | cut at 300 ms, `i/o timeout` | true | not printed | not printed | 400 at 300 ms |

Consequences (authority: inference):

- On HTTP/1.1 the deadline cut also cancels the request context, so `wafhop.IsClientGone` (`ctx.Err() != nil || Canceled || context.DeadlineExceeded || io.ErrUnexpectedEOF`, `pkg/wafhop/body.go`) classifies it as a client disconnect. Check the timer flag (`fired`) or `errors.Is(err, os.ErrDeadlineExceeded)` before `IsClientGone`.
- The response still reaches the client after an HTTP/1.1 read-deadline cut.
- `time.AfterFunc` + `ResponseController.SetReadDeadline` + the `Timer.Stop` flag work in Yaegi-interpreted code.

## Not measured

- HTTP/3 (quic-go). Traefik's own HTTP/3 read timeout uses `ResponseController.SetReadDeadline`; see `../ext_traefik_plugins_body-read-deadline/`.
- A plugin deadline through a Traefik v3.7.19 binary (the mock e2e must measure it).

## Sources

- Source: `golang/go@go1.25.6:src/net/http/transfer.go`, `h2_bundle.go`, `server.go`, `responsecontroller.go`
- Probe (authority: inference): `.sources/local-go1256-body-deadline-probe.md` (2026-11-14), `.sources/local-go1256-body-deadline-probe-2026-11-23.md`
- Extracts: `.sources/`
