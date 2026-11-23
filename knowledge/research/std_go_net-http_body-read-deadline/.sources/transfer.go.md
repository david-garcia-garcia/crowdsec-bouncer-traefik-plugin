---
url: https://github.com/golang/go/blob/go1.25.6/src/net/http/transfer.go
title: net/http body.Read and body.Close (HTTP/1.x request body)
fetched: 2026-11-14
authority: source
ref: golang/go@go1.25.6:src/net/http/transfer.go
---

`func (b *body) Read` (L831): `b.mu.Lock(); defer b.mu.Unlock()`, then `readLocked`. The mutex is held for the whole underlying `b.src.Read`.

`func (b *body) Close` (L971): takes the same `b.mu.Lock()` first. For a server request with `doEarlyClose` (L984) it either gives up (declared Content-Length with more than `maxPostHandlerReadBytes` left) or drains with `io.CopyN(io.Discard, bodyLocked{b}, maxPostHandlerReadBytes)` (L995). Default case drains with `io.Copy(io.Discard, bodyLocked{b})`. Then `b.closed = true`.

Consequence (reading of the code): a `Close` from another goroutine waits for an in-flight `Read` to release `b.mu`. It does not interrupt that `Read`.
