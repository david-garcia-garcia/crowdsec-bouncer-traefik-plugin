---
url: https://github.com/traefik/traefik/blob/83c3499fc31c96e9f80ea0bba4d975f608c7061d/pkg/middlewares/forwardedheaders/forwarded_header.go
title: forwarded_header.go
fetched: 2026-09-18
authority: source
ref: github.com/traefik/traefik@83c3499fc31c96e9f80ea0bba4d975f608c7061d:pkg/middlewares/forwardedheaders/forwarded_header.go
---

XForwarded is an HTTP handler wrapper that sets X-Forwarded headers. Unless insecure is set, it first removes all existing values for those headers if the remote address is not one of the trusted ones.

ServeHTTP: if !insecure && !isTrustedIP(RemoteAddr), DeleteXForwardedHeaders. Then rewrite.

isTrustedIP: false when ipChecker is nil (empty trustedIPs). Otherwise ipChecker.IsAuthorized(ip).

DeleteXForwardedHeaders strips managed X-headers including X-Forwarded-Proto and underscore variants (X_Forwarded_Proto).

rewrite: if X-Forwarded-Proto is empty, set wss/ws for websocket else https/http from Request.TLS != nil. A non-empty proto is left unchanged.

forwardedPort treats proto as https/wss only when the header value equals "https" or "wss" exactly.
