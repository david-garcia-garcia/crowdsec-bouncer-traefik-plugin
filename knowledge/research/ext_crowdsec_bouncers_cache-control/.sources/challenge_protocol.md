---
url: https://docs.crowdsec.net/docs/next/appsec/bot_detection/challenge_protocol.md
title: Bot Detection Challenge Protocol
fetched: 2026-09-25
authority: official
---

Challenge envelope example user_headers:

- Content-Type: ["text/html; charset=utf-8"]
- Cache-Control: ["no-cache, no-store"]
- Content-Security-Policy: [default-src 'self'; script-src 'self' 'unsafe-inline'; ...]

A challenge is a complete HTTP response the bouncer relays unchanged. Ban and captcha are verdicts the remediation component renders from its own templates.
