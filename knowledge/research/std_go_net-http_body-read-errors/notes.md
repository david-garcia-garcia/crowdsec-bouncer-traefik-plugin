# Request body read errors on client disconnect

What `io.ReadAll` surfaces when the upstream client stops sending the request body before EOF.

Fetched: 2026-09-21. Revised: 2026-11-15 against the Go 1.25.6 standard library source (`net/http/h2_bundle.go`, `net/http/server.go`) and real net/http servers. Module `go` directive: 1.22.12.

## io.ReadAll propagates the reader error

`io.ReadAll` reads until EOF or a non-nil error from `Read`. Any mid-stream `Read` error is returned as is; `newAppsecBodyRequest` in `pkg/appsec/query.go` classifies it. ([io.ReadAll](https://pkg.go.dev/io#ReadAll))

## What a real net/http server returns

Measured with real servers (`pkg/appsec/zzz_client_body_read_protocols_test.go`). `ctx` is the inbound request context when the read fails.

| Client action | Read error | `ctx.Err()` |
|---|---|---|
| HTTP/2 stream reset (`RST_STREAM` `CANCEL`) | unexported `http2StreamError` (`stream error: stream ID n; CANCEL`); no `Is`/`Unwrap` | `context.Canceled` |
| HTTP/2 upload slower than the server `ReadTimeout` | `fmt.Errorf("%w", os.ErrDeadlineExceeded)` (`i/o timeout`) | `nil` |
| HTTP/1.1 clean close (FIN) before `Content-Length` | `io.ErrUnexpectedEOF` | `context.Canceled` |
| HTTP/1.1 TCP reset (RST) | `*net.OpError` (ECONNRESET / WSAECONNRESET) | `context.Canceled` |
| HTTP/1.1 upload slower than the server `ReadTimeout` | `*net.OpError` wrapping `os.ErrDeadlineExceeded` | `context.Canceled` |

Why, from the source:

- HTTP/2 `processResetStream` calls `st.cancelCtx()` and then `closeStream`, which closes the body pipe with the stream error. The context is canceled before the read fails, but the error does not wrap `context.Canceled`.
- HTTP/2 `onReadTimeout` closes the body with a wrapped `os.ErrDeadlineExceeded` and does not cancel the context.
- HTTP/1.1 `connReader.handleReadError` cancels the connection context before the read error reaches the handler.
- `os.ErrDeadlineExceeded` is not `context.DeadlineExceeded` for `errors.Is`.
- HTTP/2 connection loss: `closeAllStreamsOnConnClose` calls `closeStream` with `errors.New("client disconnected")`, which closes the body **before** `st.cancelCtx()`. A handler can see that read error while the context is still live (a narrow race, not measured).

The earlier version of this note inferred that an HTTP/2 `CANCEL` surfaces as `context.Canceled` on the body read. The source and the measurement contradict it: only the request context says so.

## Distinction for product code

The canceled request context is the reliable client-gone signal; check it before the error. `errors.Is` for `context.Canceled`, `context.DeadlineExceeded`, and `io.ErrUnexpectedEOF` stays as a fallback for bodies that do wrap them. A read error with a live context means the request never arrived whole: answer 400, not a ban, the same as upstream PR [#401](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/401). That also covers the HTTP/2 connection-loss race above: the gone client gets a 400 it never reads, with no ban and no dropped metrics.

Not measured: HTTP/3 (quic-go is not a dependency of this module), and Traefik itself in front of the plugin. Traefik serves HTTP/1.1 and HTTP/2 with the Go net/http server, so the same errors are expected (inference).

## Sources

- Official: [io.ReadAll](https://pkg.go.dev/io#ReadAll), [context package](https://pkg.go.dev/context)
- Go 1.25.6 source: `net/http/h2_bundle.go` (`processResetStream`, `closeStream`, `closeAllStreamsOnConnClose`, `onReadTimeout`), `net/http/server.go` (`connReader.handleReadError`)
- Upstream: [maxlerebourg/crowdsec-bouncer-traefik-plugin#395](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/395), PR [#401](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/401)
