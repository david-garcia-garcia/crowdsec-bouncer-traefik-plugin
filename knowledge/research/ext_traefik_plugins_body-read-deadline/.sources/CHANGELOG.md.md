---
url: https://github.com/traefik/traefik/blob/v3.7.19/CHANGELOG.md
ref: traefik/traefik@v3.7.19:CHANGELOG.md
title: Traefik CHANGELOG — v3.7.12 to v3.7.19 entries on deadlines, HTTP/3 timeouts, Yaegi
fetched: 2026-11-23
authority: source
---

Section headers: v3.7.19 L1, v3.7.18 L20, v3.7.17 L66, v3.7.13 L209, v3.7.12 L249, v3.7.11 L285.

- L77 (v3.7.17 section): "**[middleware]** Fix broken flush, hijack, and deadlines in wrapped ResponseWriters (#14082 @Neffi42)".
- L34 (v3.7.18 section): "**[plugins]** Bump github.com/traefik/yaegi to v0.16.3 (#14231 @juliens)". Also L59, in the v2.11.62 section. Not in the v3.7.19 section.
- L255 (v3.7.12 section): "**[http3]** Apply read timeout, idle timeout, and max header bytes for HTTP/3 (#13717 @gndz07)". Also L277, in the v2.11.56 section. Not in the v3.7.13 section.
- v3.7.19 section (L1-11) bug fixes: quic-go v0.65.0, klauspost/compress v1.20.4, x/crypto v0.59.0. No deadline, wrapper or plugin entry.

`go.mod` at v3.7.19, L78: `github.com/traefik/yaegi v0.16.3` (https://github.com/traefik/traefik/blob/v3.7.19/go.mod).
