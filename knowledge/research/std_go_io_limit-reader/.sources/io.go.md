---
url: https://github.com/golang/go/blob/go1.25.6/src/io/io.go
title: io.LimitReader and LimitedReader.Read
fetched: 2026-09-17
authority: source
ref: golang/go@go1.25.6:src/io/io.go
---

LimitReader returns `&LimitedReader{r, n}`.

LimitedReader.Read: if `l.N <= 0` return `0, EOF` without reading `R`. Otherwise cap the buffer to `N`, read, subtract.

Godoc on the type: Read returns EOF when `N <= 0` or when the underlying `R` returns EOF.

Also: https://pkg.go.dev/io#LimitedReader (authority: official) — same `N <= 0` sentence.
