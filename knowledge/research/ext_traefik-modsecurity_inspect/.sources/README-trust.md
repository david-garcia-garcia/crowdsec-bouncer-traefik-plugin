---
url: https://github.com/david-garcia-garcia/traefik-modsecurity/blob/e860d2494f41d49172f2d8aae916615c8ee356e1/README.md
title: README Trust this middleware
fetched: 2026-10-12
authority: official
ref: github.com/david-garcia-garcia/traefik-modsecurity@e860d2494f41d49172f2d8aae916615c8ee356e1:README.md
---

Copying headers is not enough for ModSecurity to treat the visitor as the client. REMOTE_ADDR stays the Traefik-to-sidecar TCP hop until CRS is told to trust Traefik.

What this plugin sends to modSecurityUrl:
- Sets the sidecar request Host to the incoming Host.
- Copies Traefik’s headers as-is, including X-Real-Ip when Traefik already set it, and leftover X-Forwarded-For only if Traefik left one.
- Does not append RemoteAddr to X-Forwarded-For.
- Does not set X-Real-IP.

Traefik entrypoint forwardedheaders is the source of truth. CRS / ModSecurity does not read those headers as REMOTE_ADDR on its own.

Apache demo: REMOTEIP_HEADER X-Real-IP, REMOTEIP_INT_PROXY RFC1918; 4.3.0 pin hardcodes RemoteIPHeader X-Forwarded-For so the drain vhost overlay is required. nginx test compose: REAL_IP_HEADER / SET_REAL_IP_FROM / drain overlays. Do not set 0.0.0.0/0. Without this, every deny is attributed to the Traefik container IP.
