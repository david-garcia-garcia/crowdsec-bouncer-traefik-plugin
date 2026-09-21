# Traefik entrypoint X-Forwarded-Proto

Traefik sanitizes `X-Forwarded-Proto` on the **entrypoint** before plugin middleware runs. A Yaegi plugin’s `http.Request` sees that already-decided header. `Request.TLS` is the TLS state of the connection **to Traefik**, not the client-to-edge protocol.

## Entrypoint owns proto trust

Unless `forwardedHeaders.insecure` is true, Traefik deletes managed `X-Forwarded-*` headers (including `X-Forwarded-Proto` and underscore aliases) when `RemoteAddr` is not in `forwardedHeaders.trustedIPs`. An empty trusted list means no peer is trusted, so incoming proto is stripped.

Owner: `github.com/traefik/traefik@83c3499fc31c96e9f80ea0bba4d975f608c7061d:pkg/middlewares/forwardedheaders/forwarded_header.go` (`ServeHTTP`, `DeleteXForwardedHeaders`, `isTrustedIP`). Extract: `.sources/forwarded_header.go.md`.

Official position: the forwarded-header trust boundary is entrypoint-level. `trustedIPs` / `insecure` decide once before any middleware. Re-deciding per middleware is the design they avoid.

Owner: [Traefik Security Decisions — Forwarded Headers and Client Identity](https://doc.traefik.io/traefik/master/contributing/security-decisions/). Extract: `.sources/security-decisions.md`.

Entrypoint keys: `forwardedHeaders.insecure` (default false, test-only), `forwardedHeaders.trustedIPs`.

Owner: [Traefik EntryPoints — Forwarded Headers](https://doc.traefik.io/traefik/master/reference/install-configuration/entrypoints/). Extract: `.sources/entrypoints.md`.

## What the plugin then sees

After the strip (or skip when insecure/trusted), Traefik `rewrite`s proto only when the header is empty:

- websocket + `Request.TLS != nil` → `wss`; websocket without TLS → `ws`
- else `Request.TLS != nil` → `https`; else `http`

A kept incoming value is left as-is. Traefik’s own port helper compares that value with exact `== "https"` or `== "wss"` (no comma split, no `EqualFold`).

Owner: same `forwarded_header.go` (`rewrite`, `forwardedPort`). Extract: `.sources/forwarded_header.go.md`.

Therefore `TLS == nil` with `X-Forwarded-Proto: https` on a plugin request means the entrypoint already trusted the hop (or `insecure`) and kept the edge proto. Default Traefik (no trusted IPs, insecure false) overwrites proto to `http` when TLS is nil.

`GetRemoteIP` in this plugin owns **client address**, not scheme. A second hop-trust check on proto reconstructs a fact Traefik already decided, with a possibly different CIDR list.

## Header meaning

`X-Forwarded-Proto` is a de-facto request header for the protocol the client used to reach a proxy (`http` or `https`). Not a current RFC; the standardized sibling is `Forwarded`. MDN examples are a single token (`X-Forwarded-Proto: https`). Other vendor spellings (`Front-End-Https`, `X-Forwarded-Protocol`, `X-Url-Scheme`) exist and are not this header.

Owner: [MDN — X-Forwarded-Proto](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-Proto). Extract: `.sources/mdn-x-forwarded-proto.md`.
