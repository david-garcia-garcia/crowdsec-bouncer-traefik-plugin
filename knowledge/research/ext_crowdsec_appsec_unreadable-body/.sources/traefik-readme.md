---
ref: github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin@04d928872df12bdb9d953b2d92948e0b89692d6a:README.md
title: Traefik plugin README
fetched: 2026-09-06
authority: source
---

CrowdsecAppsecUnreadableBodyBlock:
- bool, default: true
- HTTP/2 or HTTP/3 without Content-Length (bidirectional gRPC stream).
- false: forwarded to Appsec Server with headers only (body streams through untouched).
- true: blocked outright.
- Mirrors reference bouncers' APPSEC_DROP_UNREADABLE_BODY option.

Example YAML (line ~628): crowdsecAppsecUnreadableBodyBlock: false (operator override, not the documented default).
