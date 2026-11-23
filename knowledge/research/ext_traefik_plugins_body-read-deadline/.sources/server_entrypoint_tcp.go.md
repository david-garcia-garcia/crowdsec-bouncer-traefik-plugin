---
url: https://github.com/traefik/traefik/blob/v3.7.19/pkg/server/server_entrypoint_tcp.go
ref: traefik/traefik@v3.7.19:pkg/server/server_entrypoint_tcp.go
title: Traefik TCP entry point — accept-time deadlines, writeCloser, Protocols, trackedConnection
fetched: 2026-11-23
authority: source
---

Read from the local module cache `github.com/traefik/traefik/v3@v3.7.19`.

L287-310, accept loop: `writeCloser, err := writeCloser(conn)`, then in a goroutine:

> // Enforce read/write deadlines at the connection level,
> // because when we're peeking the first byte to determine whether we are doing TLS,
> // the deadlines at the server level are not taken into account.

`if RespondingTimeouts.ReadTimeout > 0 { writeCloser.SetReadDeadline(time.Now().Add(ReadTimeout)) }` (L296-301); same for WriteTimeout (L303-308); then `e.switcher.ServeTCP(newTrackedConnection(writeCloser, e.tracker))` (L310).

L409-436: `writeCloserWrapper` embeds `net.Conn`; `writeCloser(conn)` returns the `*net.TCPConn` itself, or for a `*proxyproto.Conn` a `writeCloserWrapper{Conn: <proxyproto conn>, writeCloser: <underlying TCPConn>}`; any other type is an error.

L677-682: `protocols.SetHTTP1(true)`, `SetHTTP2(true)`, `SetUnencryptedHTTP2(withH2c)`, with the comment "With the addition of UnencryptedHTTP2 in http.Server#Protocols in go1.24 setting the h2c handler is not necessary anymore."

L787-791: `&http.Server{Protocols: &protocols, Handler: handler, ..., ReadTimeout: RespondingTimeouts.ReadTimeout, WriteTimeout: ..., IdleTimeout: ...}`.

L823-840: `newTrackedConnection` returns `&trackedConnection{WriteCloser: conn, ...}`; `trackedConnection` embeds `tcp.WriteCloser` and overrides only `Close`.

`pkg/tcp/handler.go` L22-23: `type WriteCloser interface { net.Conn; CloseWrite() error }` (CloseWrite on the following lines).

`pkg/config/static/static_config.go` L51: `DefaultReadTimeout = 60 * time.Second`.
