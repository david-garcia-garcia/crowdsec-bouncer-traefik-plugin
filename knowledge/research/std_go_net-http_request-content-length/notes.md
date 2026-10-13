# Request ContentLength versus Content-Length header

How Go’s HTTP client decides the outbound `Content-Length` on a request built with `NewRequest` and then given extra headers.

Fetched: 2026-09-17. Pin: Go 1.25.6.

## The field is the owner

`Request.ContentLength` records body length. `-1` is unknown. For **client** requests, `0` with a non-nil Body is also treated as unknown. ([Request](https://pkg.go.dev/net/http#Request), extract `.sources/request.md`)

`NewRequest` / `NewRequestWithContext`: if `body` is `*bytes.Buffer`, `*bytes.Reader`, or `*strings.Reader`, `ContentLength` is set to that reader’s `Len()`. ([request.go](https://github.com/golang/go/blob/go1.25.6/src/net/http/request.go), extract `.sources/request.go.md`)

`outgoingLength()` (used by the client write path) returns `0` when Body is nil or `NoBody`; otherwise the `ContentLength` **field** if it is non-zero; otherwise `-1`. It does not read the `Content-Length` header. ([request.go](https://github.com/golang/go/blob/go1.25.6/src/net/http/request.go))

## Header values may be ignored

Request docs: for client requests, headers such as `Content-Length` and `Connection` are written when needed and **values in Header may be ignored**. `Request.Write` consults the `ContentLength` field. If Body is present, Content-Length is `<= 0`, and Transfer-Encoding is not `identity`, Write adds `Transfer-Encoding: chunked`. ([Request](https://pkg.go.dev/net/http#Request); [Request.Write](https://pkg.go.dev/net/http#Request.Write))

`transferWriter.writeHeader` emits `Content-Length` from the sanitized field and **skips** `Content-Length` and `Transfer-Encoding` keys when copying the Header map. ([transfer.go](https://github.com/golang/go/blob/go1.25.6/src/net/http/transfer.go), extract `.sources/transfer.go.md`)

So after `NewRequest(..., bytes.NewBuffer(forwarded))` plus `Header.Add` of the client’s original `Content-Length`, **Client.Do still writes the field** (the forwarded length). The copied header does not win on the wire. The Header map can still disagree with the bytes in Body until something overwrites or deletes it.

## DELETE usually lacks a body

`requestMethodUsuallyLacksBody` includes `DELETE` (with GET, HEAD, OPTIONS, …). Transport uses that when `outgoingLength` is `-1` to decide whether to probe a non-nil Body for chunked send. ([request.go](https://github.com/golang/go/blob/go1.25.6/src/net/http/request.go))

## Sources

- Official: [net/http.Request](https://pkg.go.dev/net/http#Request), [Request.Write](https://pkg.go.dev/net/http#Request.Write)
- Source: `golang/go@go1.25.6:src/net/http/request.go`, `golang/go@go1.25.6:src/net/http/transfer.go`
- Extracts: `.sources/`
