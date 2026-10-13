---
url: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/399
title: "keep the stream and metrics tickers on their own channels"
fetched: 2026-09-26
authority: comment
---

Open PR. Head dca428958ae6c50e3750fbc9303be9a87a2c0553 (fix/377-yaegi-shared-select). Fixes #377.

Body: Traefik runs the plugin under yaegi v0.16.1; that version (and yaegi master per the body) builds the select case list once per statement and shares it. Stream and metrics loops both ran the same select in startTicker. Stream loop on the metrics channel → gap of one or two metrics intervals (1200 s in #377), missing metrics push at resume, stream work twice. Metrics loop on the stream channel → dropped stream tick, extra metrics push.

`runTicker` ranges the ticker channel so yaegi builds the receive on every execution. stop channel was never signalled; startTicker returns *time.Ticker.

Checks claimed in the body (not re-run this research): under yaegi v0.16.1, two goroutines / one select each → 13,178 cross-channel receives in 5.1M vs 0 in 12.1M after the change; Traefik 3.7.9 plugin soak 1s/2s/25 min → 3 stream gaps vs 0. Race needs separate CPUs. Test Test_runTicker_keepsEachTickerOnItsOwnChannel fails under yaegi test with the old select.
