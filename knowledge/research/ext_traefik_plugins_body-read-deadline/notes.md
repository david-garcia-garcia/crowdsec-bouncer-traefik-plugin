# Traefik plugin request body read deadline

Whether a Yaegi plugin running inside Traefik can cut an in-flight request body read with `http.NewResponseController(w).SetReadDeadline`, per protocol, and what Traefik itself already does with read deadlines. Go-side behaviour (which error the read returns, HTTP/1 vs HTTP/2 mechanics) lives in `../std_go_net-http_body-read-deadline/`.

Fetched: 2026-11-23. Pin: `traefik/traefik@v3.7.19`, read from the local module cache `github.com/traefik/traefik/v3@v3.7.19`. Permalinks: `https://github.com/traefik/traefik/blob/v3.7.19/<path>`.

## Writer the plugin receives

- Traefik wraps every Yaegi and Wasm plugin with `wrapExternal`: the plugin's `ServeHTTP` gets an `entryWriter` around the writer that reached the plugin. `entryWriter` has no `SetReadDeadline` of its own and exposes `Unwrap()` to the inner writer. (`pkg/plugins/external.go` L31-46, L60-93; `pkg/plugins/middlewareyaegi.go` L62-65; `.sources/external.go.md`)
- The `next` handler gets an `exitWriter` only when the plugin passes on a different writer. Its `SetReadDeadline` tries the plugin's writer and falls back to the entry writer on `http.ErrNotSupported`; `Unwrap()` returns the plugin's writer. (`pkg/plugins/external.go` L48-57, L96-146)
- In v3.7.19 every ResponseWriter wrapper under `pkg/middlewares` (capture, compress, customerrors x2, observability/status_code, recovery, response_modifier, retry, ingressnginx/snippet) and both plugin writers implement `Unwrap() http.ResponseWriter`. The only `pkg/` writer holders without it (`proxy/fast` writeFlusher, loadbalancer mirror) sit after the middlewares. (`.sources/responsewriter-unwrap.md`)
- So `ResponseController.SetReadDeadline` from the plugin can walk `Unwrap` down to the `net/http` server writer (HTTP/1 `*response`, HTTP/2 stream writer). (authority: inference — from the files above plus `../std_go_net-http_body-read-deadline/` § ResponseController and wrappers; not measured on v3.7.19)

## HTTP/1.1 connection

- At accept, Traefik sets the raw connection read deadline to `now + respondingTimeouts.readTimeout`, "because when we're peeking the first byte to determine whether we are doing TLS, the deadlines at the server level are not taken into account". The `http.Server` also gets `ReadTimeout`. Default `readTimeout` is 60 s. (`pkg/server/server_entrypoint_tcp.go` L287-310, L787-791; `pkg/config/static/static_config.go` L51; `.sources/server_entrypoint_tcp.go.md`)
- The connection handed on is `trackedConnection`, which embeds `tcp.WriteCloser` (`net.Conn` + `CloseWrite`) over the `*net.TCPConn` or a `writeCloserWrapper` over a proxy-protocol conn; only `Close` is overridden, so `SetReadDeadline` reaches the TCP conn. (`server_entrypoint_tcp.go` L409-436, L823-840; `pkg/tcp/handler.go` L22)
- HTTP/1 `SetReadDeadline` writes the same conn deadline as `ReadTimeout`; the last call wins, so a plugin deadline replaces Traefik's readTimeout deadline for that request. A plugin should pass the earlier of the two. (authority: inference — `../std_go_net-http_body-read-deadline/` § ReadTimeout interaction)

## HTTP/2 cleartext (h2c)

h2c is enabled with `http.Protocols.SetUnencryptedHTTP2(withH2c)` on the `http.Server`, not an h2c handler wrapper. (`server_entrypoint_tcp.go` L677-682, L788) So h2c streams are served by `net/http`'s own HTTP/2 server and the HTTP/2 rows of the Go note apply. (authority: inference)

## HTTP/3

For HTTP/3 Traefik itself calls `http.NewResponseController(rw).SetReadDeadline(now + readTimeout)` when `req.ContentLength != 0`. Its comment: quic-go never leaves `req.Body` nil or `http.NoBody`, and `ContentLength` is -1 when the length is unknown. (`pkg/server/server_entrypoint_tcp_http3.go` L68-71, L119-133; `.sources/server_entrypoint_tcp_http3.go.md`) So the quic-go writer supports `SetReadDeadline`, and a plugin deadline through the same controller should work on HTTP/3. (authority: inference — not measured)

## Version history

Owner: `CHANGELOG.md` at v3.7.19. Extract: `.sources/CHANGELOG.md.md`.

- v3.7.12: "Apply read timeout, idle timeout, and max header bytes for HTTP/3" (#13717). (L255; not in v3.7.13)
- v3.7.17: "Fix broken flush, hijack, and deadlines in wrapped ResponseWriters" (#14082). (L77)
- v3.7.18: "Bump github.com/traefik/yaegi to v0.16.3" (#14231). (L34; not in the v3.7.19 section) `go.mod` at v3.7.19 requires `github.com/traefik/yaegi v0.16.3` (L78).

## v3.7.11 result vs v3.7.19 (authority: inference)

- The superseded PR #204 measured on Traefik v3.7.11 that a plugin's `ResponseController.SetReadDeadline` did **not** cut an HTTP/1.1 chunked body read, while HTTP/2 was cut. (`../std_go_net-http_body-read-deadline/` § Measured on the superseded PR #204 branch)
- #14082 (v3.7.17) touches deadlines in wrapped ResponseWriters and is a plausible reason that result changed by v3.7.19. Not established from the PR diff (v3.7.11 source not read).
- **Not measured on v3.7.19.** The mock e2e must measure the HTTP/1.1 chunked cut through a real Traefik v3.7.19 binary before relying on it.

## Sources

- Source: `traefik/traefik@v3.7.19:pkg/server/server_entrypoint_tcp.go`, `pkg/plugins/external.go`, `pkg/plugins/middlewareyaegi.go`, `pkg/server/server_entrypoint_tcp_http3.go`, `pkg/config/static/static_config.go`, `pkg/tcp/handler.go`, `CHANGELOG.md`, `go.mod`, grep of `Unwrap() http.ResponseWriter` under `pkg/`
- Extracts: `.sources/`
