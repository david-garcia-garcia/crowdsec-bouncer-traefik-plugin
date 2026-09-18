---
url: https://github.com/golang/go/blob/go1.25.6/src/net/http/request.go
title: NewRequestWithContext and outgoingLength
fetched: 2026-09-17
authority: source
ref: golang/go@go1.25.6:src/net/http/request.go
---

NewRequestWithContext: *bytes.Buffer / *bytes.Reader / *strings.Reader set ContentLength to Len().

outgoingLength: Body nil or NoBody → 0; else ContentLength field if != 0; else -1. Does not read Header.

requestMethodUsuallyLacksBody: GET, HEAD, DELETE, OPTIONS, PROPFIND, SEARCH.
