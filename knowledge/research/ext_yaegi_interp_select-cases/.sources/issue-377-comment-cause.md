---
url: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/377#issuecomment-5837369074
title: "issue 377 comment: Found the cause (yaegi select sharing)"
fetched: 2026-09-26
authority: comment
---

mathieuHa, 2026-09-25. Claims the cause is yaegi v0.16.1 `_select` sharing the select case list across goroutines; stream and metrics loops ran the same select in startTicker; co-fire can leave the stream loop waiting on the metrics channel for one or two metrics intervals (1200 s with defaults). Points at PR 399 (`for range ticker.C`). Says GOMAXPROCS=1 makes the race ~1000× rarer. Workaround: metricsUpdateIntervalSeconds: 0.

Not the owner of interpreter behavior; see interp/run.go extracts.
