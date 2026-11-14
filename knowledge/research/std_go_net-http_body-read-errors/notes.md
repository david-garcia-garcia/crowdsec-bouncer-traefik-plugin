# Request body read errors on client disconnect

What `io.ReadAll` surfaces when the upstream client stops sending the request body before EOF.

Fetched: 2026-09-21. Pin: Go 1.22.12 (module `go` directive in this worktree). Deadline row corrected 2026-11-14 against Go 1.25.6.

## io.ReadAll propagates the reader error

`io.ReadAll` reads until EOF or a non-nil error from `Read`. Any mid-stream `Read` error is returned wrapped only by the caller (`fmt.Errorf("appsecQuery:GetBody %w", err)` in `pkg/appsec/query.go` `newAppsecBodyRequest`). ([io.ReadAll](https://pkg.go.dev/io#ReadAll))

## Common cancel/disconnect errors

| Error | Typical cause |
|-------|----------------|
| `context.Canceled` | Request context canceled (client gone, handler timeout, HTTP/2 RST) |
| `context.DeadlineExceeded` | ~~Body read exceeded deadline on request context~~ **Corrected 2026-11-14:** not what a server read deadline returns; see below |
| wrapped `os.ErrDeadlineExceeded` (`i/o timeout`) | `http.Server.ReadTimeout` or `ResponseController.SetReadDeadline` expired (HTTP/1.1 and HTTP/2) |
| `io.ErrUnexpectedEOF` | Fewer bytes than `Content-Length` before connection close |
| Opaque `errors.New("…")` | Custom `Body` implementations or proxy-specific wrappers |

**Correction (2026-11-14, pin Go 1.25.6).** The original `context.DeadlineExceeded` row was inference and is wrong for server read deadlines. When `http.Server.ReadTimeout` or `http.ResponseController.SetReadDeadline` expires, the body `Read` returns a wrapped `os.ErrDeadlineExceeded` (text `i/o timeout`; HTTP/1.1 shows `read tcp …: i/o timeout`), on both HTTP/1.1 and HTTP/2. `errors.Is(err, context.DeadlineExceeded)` is false; use `errors.Is(err, os.ErrDeadlineExceeded)`. HTTP/2 owner: `onReadTimeout` closes the body with `fmt.Errorf("%w", os.ErrDeadlineExceeded)` (`golang/go@go1.25.6:src/net/http/h2_bundle.go` L5951). Both protocols measured by local probe (authority: inference). Details, per-protocol abort mechanisms and extracts: `../std_go_net-http_body-read-deadline/`.

HTTP/2 stream `CANCEL` in Go’s server often cancels the request context, which surfaces as `context.Canceled` on body reads. Exact wiring depends on Traefik’s `http.Request` and whether the body is the standard `body` type. (authority: inference — repro uses synthetic `errReader`; matches upstream issue #395 report.)

## Distinction for product code

Treat **client-initiated** abort (`errors.Is` cancel/deadline/unexpected EOF) separately from **server-side** read faults (storage, TLS alert on read) when deciding fail-open vs ban. Generic errors without classification remain conservative (ban) unless proven benign.

## Sources

- Official: [io.ReadAll](https://pkg.go.dev/io#ReadAll), [context package](https://pkg.go.dev/context)
- Local repro: temp module copy, `explore_repro_test.go` — `C:\Users\DAVIDG~1\AppData\Local\Temp\opd-explore-appsec-cancel-72058561`
- Deadline correction: `golang/go@go1.25.6:src/net/http/h2_bundle.go` ([permalink](https://github.com/golang/go/blob/go1.25.6/src/net/http/h2_bundle.go)); probe and extracts in `../std_go_net-http_body-read-deadline/.sources/`
