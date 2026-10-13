---
url: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/dca428958ae6c50e3750fbc9303be9a87a2c0553/bouncer.go
title: bouncer.go startTicker / runTicker (PR 399)
fetched: 2026-09-26
authority: source
ref: github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin@dca428958ae6c50e3750fbc9303be9a87a2c0553:bouncer.go
---

Before: streamTicker/metricsTicker are chan bool. startTicker(name, interval, log, work) created a ticker, a buffered stop chan, and a goroutine `for { select { case <-ticker.C: go work(); case <-stop: return } }`, returning stop.

After: those globals are *time.Ticker. startTicker(interval, work) does time.NewTicker, `go runTicker(ticker.C, work)`, returns the ticker.

runTicker(ticks <-chan time.Time, work func()) is `for range ticks { go work() }`. No stop channel.
