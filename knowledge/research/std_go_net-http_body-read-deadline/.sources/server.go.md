---
url: https://github.com/golang/go/blob/go1.25.6/src/net/http/server.go
title: net/http Server.ReadTimeout and HTTP/1 response.SetReadDeadline
fetched: 2026-11-14
authority: source
ref: golang/go@go1.25.6:src/net/http/server.go
---

`Server.ReadTimeout` doc (L3015-3023): "ReadTimeout is the maximum duration for reading the entire request, including the body. A zero or negative value means there will be no timeout." Doc also says most users prefer `ReadHeaderTimeout` because ReadTimeout does not allow per-request decisions.

HTTP/1 `readRequest` (L1025-1026, L1085-1086): `wholeReqDeadline = t0.Add(ReadTimeout)` and, after headers, `c.rwc.SetReadDeadline(wholeReqDeadline)` on the `net.Conn`.

HTTP/1 `func (c *response) SetReadDeadline` (L499-500): `return c.conn.rwc.SetReadDeadline(deadline)`. Same `net.Conn` deadline as ReadTimeout; the last call wins.
