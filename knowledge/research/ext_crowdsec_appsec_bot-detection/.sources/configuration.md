---
url: https://docs.crowdsec.net/docs/next/appsec/bot_detection/configuration.md
title: Bot detection configuration
fetched: 2026-09-05
authority: official
---

Settings live under top-level challenge: in an appsec-config YAML. Multiple loaded configs merge field by field.

cookie_ttl default 12h. Cookie carries its own not_after sealed under the master cookie key; rotating the per-epoch sign key does not invalidate issued cookies.

master_secret required when more than one AppSec instance; otherwise cookies from one are rejected by another.

Bouncer must forward /crowdsec-internal/challenge/* unchanged (points at intro prerequisites).
