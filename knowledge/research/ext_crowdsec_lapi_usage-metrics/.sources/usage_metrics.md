---
url: https://docs.crowdsec.net/docs/next/observability/usage_metrics
title: Usage Metrics
fetched: 2026-09-05
authority: official
---

Requires CrowdSec v1.6.3. View locally with cscli metrics show bouncers. OS with cscli bouncers inspect XXX.
Supported origins: crowdsec, CAPI, cscli, cscli-import, appsec, console, lists:XXX (XXX = subscribed blocklist name).
Firewall reports dropped bytes/packets; OpenResty reports dropped HTTP requests.
active_decisions counts may differ from cscli decisions list because of stream filters (scope, scenarios, etc.) and LAPI dedup.
Does not define a usage-metrics label named scenario.
