# Request body read errors on client disconnect

What `io.ReadAll` surfaces when the upstream client stops sending the request body before EOF.

Fetched: 2026-09-21. Pin: Go 1.22.12 (module `go` directive in this worktree).

## io.ReadAll propagates the reader error

`io.ReadAll` reads until EOF or a non-nil error from `Read`. Any mid-stream `Read` error is returned wrapped only by the caller (`fmt.Errorf("appsecQuery:GetBody %w", err)` in `pkg/appsec/query.go` `newAppsecBodyRequest`). ([io.ReadAll](https://pkg.go.dev/io#ReadAll))

## Common cancel/disconnect errors

| Error | Typical cause |
|-------|----------------|
| `context.Canceled` | Request context canceled (client gone, handler timeout, HTTP/2 RST) |
| `context.DeadlineExceeded` | Body read exceeded deadline on request context |
| `io.ErrUnexpectedEOF` | Fewer bytes than `Content-Length` before connection close |
| Opaque `errors.New("…")` | Custom `Body` implementations or proxy-specific wrappers |

HTTP/2 stream `CANCEL` in Go’s server often cancels the request context, which surfaces as `context.Canceled` on body reads. Exact wiring depends on Traefik’s `http.Request` and whether the body is the standard `body` type. (authority: inference — repro uses synthetic `errReader`; matches upstream issue #395 report.)

## Distinction for product code

Treat **client-initiated** abort (`errors.Is` cancel/deadline/unexpected EOF) separately from **server-side** read faults (storage, TLS alert on read) when deciding fail-open vs ban. Generic errors without classification remain conservative (ban) unless proven benign.

## Sources

- Official: [io.ReadAll](https://pkg.go.dev/io#ReadAll), [context package](https://pkg.go.dev/context)
- Local repro: temp module copy, `explore_repro_test.go` — `C:\Users\DAVIDG~1\AppData\Local\Temp\opd-explore-appsec-cancel-72058561`
