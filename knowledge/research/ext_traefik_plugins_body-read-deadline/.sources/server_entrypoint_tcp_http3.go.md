---
url: https://github.com/traefik/traefik/blob/v3.7.19/pkg/server/server_entrypoint_tcp_http3.go
ref: traefik/traefik@v3.7.19:pkg/server/server_entrypoint_tcp_http3.go
title: Traefik HTTP/3 entry point — withReadTimeout
fetched: 2026-11-23
authority: source
---

L68-71: `if readTimeout != 0 { handler = withReadTimeout(ctx, handler, readTimeout) }`, wrapping the HTTPS server handler that HTTP/3 serves.

L119-133 `withReadTimeout`:

> // quic-go never leaves req.Body nil or equal to http.NoBody, so neither can be used to detect
> // an absent body. ContentLength is 0 only when the client declared no body, and -1 when the
> // length is unknown (no Content-Length header), both of which may still carry a body that
> // needs bounding.

`if req.ContentLength != 0 { http.NewResponseController(rw).SetReadDeadline(time.Now().Add(timeout)) }`; an error is logged as "Failed to set HTTP3 read timeout"; then `next.ServeHTTP(rw, req)`.
