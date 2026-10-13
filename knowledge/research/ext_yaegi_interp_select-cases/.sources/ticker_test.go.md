---
url: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/dca428958ae6c50e3750fbc9303be9a87a2c0553/ticker_test.go
title: Test_runTicker_keepsEachTickerOnItsOwnChannel (PR 399)
fetched: 2026-09-26
authority: source
ref: github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin@dca428958ae6c50e3750fbc9303be9a87a2c0553:ticker_test.go
---

New file. Test_runTicker_keepsEachTickerOnItsOwnChannel: count=20000. Two channels streamTicks and metricsTicks. Two goroutines call runTicker, each incrementing its own atomic counter and WaitGroup. Two sendTicks goroutines push count values on each channel. After Wait, fail unless both counters equal count.

Idea: each runTicker must consume only the channel it was given. Cross-channel receives would make the counts diverge (PR body: under yaegi test with the old select, example 19,997 and 20,003 of 20,000).
