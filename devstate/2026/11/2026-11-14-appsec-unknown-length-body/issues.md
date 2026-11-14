# Issues

- [ ] note large  `knowledge/debt/2026-11-14-appsec-body-timeout-http1-cut-behind-traefik.md`
  Why: behind Traefik v3.7.11 a stalled HTTP/1.1 body is blocked only when the client ends it or at Traefik's readTimeout, not at appsecBodyReadTimeoutSeconds (Traefik writer hides SetReadDeadline).
