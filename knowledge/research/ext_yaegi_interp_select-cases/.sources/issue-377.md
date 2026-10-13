---
url: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/377
title: "Plugin periodically stops calling GET /v1/decisions/stream for exactly ~20 minutes, while POST /v1/usage-metrics keeps working"
fetched: 2026-09-26
authority: ticket
---

Open issue. Reporter maylo-lab, 2026-08-20. Plugin v1.7.1, Traefik v3.7.10, CrowdSec v1.7.8.

In stream mode the plugin intermittently stops GET /v1/decisions/stream for ~20 minutes (three occurrences: ~21 min, 20 min exactly, 20 min exactly), then resumes. During the freeze POST /v1/usage-metrics still fires on its own cycle. Traefik keeps serving. Last normal `handleStreamCache:updated` at 2026-08-20T04:26:35.528Z; resume at 04:46:35.529Z with a duplicate log line 1 ms later. Hypothesis in the ticket: ticker/goroutine blocked on the stream call; not confirmed.

Closed-by-PR reference (open): #399 "keep the stream and metrics tickers on their own channels".
