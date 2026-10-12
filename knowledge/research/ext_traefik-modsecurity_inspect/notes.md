# Inspect copy protocol

How [david-garcia-garcia/traefik-modsecurity](https://github.com/david-garcia-garcia/traefik-modsecurity) (`e860d2494f41d49172f2d8aae916615c8ee356e1`) copies a request to the CRS sidecar, classifies the sidecar HTTP status, and what it forwards to the client versus `next`.

Fetched: 2026-10-12.

## Copy, then classify sidecar status

The plugin sends a **copy** to `modSecurityUrl`. If the sidecar allows, Traefik forwards the original request to the application. If the sidecar blocks, the client gets that block and the app is never called. The WAF container is inspect-only: after CRS request phases it answers HTTP 200; it does not reverse-proxy to a second site. Owner: [README Architecture / How it works](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/e860d2494f41d49172f2d8aae916615c8ee356e1/README.md). Extract: `.sources/README-how-it-works.md`.

ServeHTTP classification (after a sidecar response):

| Sidecar status | Plugin action |
| --- | --- |
| **2xx** | status token `ok` (when configured); `next.ServeHTTP` |
| **3xx / 4xx** | status token `blocked`; `forwardResponse` copies sidecar status+body to the client; **no** `next` |
| **5xx** | WAF **failure**, not a block: token `error`; count a gate failure when backoff is enabled; `serveFailClosedOrNext`; sidecar 5xx body is **not** forwarded |

Owner: `github.com/david-garcia-garcia/traefik-modsecurity@e860d249:pkg/modsecurity/serve.go`. Extract: `.sources/serve.go.md`. Official How it works states the same 2xx / 3xx-4xx / 5xx split. Extract: `.sources/README-how-it-works.md`.

The HTTP client uses `CheckRedirect` → `http.ErrUseLastResponse` so a sidecar 3xx is classified as a block instead of followed. Owner: `…@e860d249:pkg/modsecurity/plugin.go`. Extract: `.sources/plugin.go.md`.

Copied block responses omit hop-by-hop headers (`Connection`, `Keep-Alive`, `Transfer-Encoding`, `Upgrade`, `Proxy-*`, `Te`, `Trailer`) and `Server`. Owner: `…@e860d249:pkg/modsecurity/serve.go` (`forwardResponse`, `omitSidecarResponseHeader`); README How it works.

## Header copy toward the sidecar (trust)

What the plugin sends to `modSecurityUrl`:

- Sets sidecar request `Host` to incoming `req.Host` (Host is not in the header map).
- Copies Traefik’s headers as-is (including `X-Real-Ip` when Traefik already set it, leftover `X-Forwarded-For` only if Traefik left one).
- Does **not** append `RemoteAddr` to `X-Forwarded-For`.
- Does **not** set `X-Real-IP`.

Owner: `…@e860d249:pkg/modsecurity/serve.go` (header loop + `proxyReq.Host = req.Host`; no XFF/X-Real-IP writes). Official: [README Trust this middleware](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/e860d2494f41d49172f2d8aae916615c8ee356e1/README.md). Extract: `.sources/README-trust.md`.

`REMOTE_ADDR` in CRS logs stays the Traefik-to-sidecar TCP hop until the CRS image is told to trust Traefik (`REMOTEIP_*` / `REAL_IP_*` on the sidecar, not this plugin). Owner: README Trust this middleware.

## failMode open|close

After Prepare, `failMode` is `open` or `close` (lowercase). Empty/omitted → `open`. Other values fail construction. Owner: `…@e860d249:pkg/modsecurity/config.go` (`FailModeOpen`, `FailModeClose`, `parseFailMode`, `Prepare`). Extract: `.sources/config.go.md`.

`serveFailClosedOrNext`: `close` writes empty HTTP 502 and does not call `next`; `open` calls `next`. Used for sidecar transport errors, sidecar 5xx, and already-unhealthy skip. Not used for inbound cancel (empty 502 without `next` regardless of failMode) or for copied 3xx/4xx. Owner: `…@e860d249:pkg/modsecurity/serve.go`; README Configuration + How it works. Extracts: `.sources/serve.go.md`, `.sources/README-configuration.md`, `.sources/README-how-it-works.md`.

## bypassRules

Each entry: optional `method` (case-insensitive; empty = any method) and optional `pathRegexp` (Go RE2, unanchored `MatchString` on `req.URL.Path`; empty = any path). Both set: both must match. Invalid regexp fails construction. Match skips sidecar, body buffer, and local verb-body reject; token `bypassrule` when the status header is configured. Owner: `…@e860d249:pkg/modsecurity/bypass.go`; `…@e860d249:pkg/modsecurity/serve.go` (match before deny/gate); README Configuration. Extracts: `.sources/bypass.go.md`, `.sources/serve.go.md`, `.sources/README-configuration.md`.

## denyVerbsWithBody

Default list (CreateConfig / omitted nil): `HEAD`, `GET`, `DELETE`, `OPTIONS`, `TRACE`, `CONNECT`. A listed method with a readable body byte → HTTP 400, no ModSecurity, no `next`, including when the WAF is already unhealthy (check runs before the gate). Explicit empty list denies nothing. Methods not on the list are inspected and forwarded. Owner: `…@e860d249:pkg/modsecurity/config.go` (`CreateConfig`, Prepare nil vs empty); `…@e860d249:pkg/modsecurity/serve.go`; README Configuration.

## maxBodySizeBytes

`readInboundBody` wraps `req.Body` with `http.MaxBytesReader` when `maxBodySizeBytes > 0`. `MaxBytesError` → HTTP 413, token `blocked`. Owner: `…@e860d249:pkg/modsecurity/body.go`; `…@e860d249:pkg/modsecurity/serve.go` (`replyInboundBodyReadFailure`). Extracts: `.sources/body.go.md`, `.sources/serve.go.md`.

**Official vs source (default):** README Configuration example and comment say default `5242880` (5 MB) and “Set to 0 for unlimited”. `CreateConfig` sets `8 * 1024 * 1024` (8 MB). `Prepare` treats `0` as omitted and fills that CreateConfig default, so `0` is not unlimited on this pin. Follow source for this version; README is stale. Owners: `…@e860d249:pkg/modsecurity/config.go`; [README Configuration](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/e860d2494f41d49172f2d8aae916615c8ee356e1/README.md).
