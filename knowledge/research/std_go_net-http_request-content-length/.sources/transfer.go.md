---
url: https://github.com/golang/go/blob/go1.25.6/src/net/http/transfer.go
title: transferWriter Content-Length write
fetched: 2026-09-17
authority: source
ref: golang/go@go1.25.6:src/net/http/transfer.go
---

newTransferWriter for a Request sets t.ContentLength from rr.outgoingLength().

writeHeader: if shouldSendContentLength, writes "Content-Length: " plus t.ContentLength. When copying remaining Header keys, skips Transfer-Encoding, Trailer, and Content-Length.
