---
url: https://docs.crowdsec.net/docs/next/appsec/bot_detection/intro.md
title: Bot detection
fetched: 2026-09-05
authority: official
---

Alpha feature: ready to try; configuration, helpers, and shipped rules may still change between releases.

Prerequisites: working AppSec; a compatible bouncer. Page lists Nginx, OpenResty, HAProxy SPOA, Traefik, Envoy (look for Bot Detection badge). That Traefik listing conflicts with the 1.8 blog and with this product's open PR/issue; see notes.md.

Engine host needs wasm compiler mode (arm64, or amd64 with SSE4.1) and executable memory mapping. Clients need JS and cookies. Cookie name implied via challenge flow; outcome carried by a cookie.

Challenge protocol page is the wire contract for adding support to a remediation component.
