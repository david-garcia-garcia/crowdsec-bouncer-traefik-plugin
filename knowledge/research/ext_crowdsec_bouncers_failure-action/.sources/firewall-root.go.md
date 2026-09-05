---
url: https://github.com/crowdsecurity/cs-firewall-bouncer/blob/1dd4492523e04a25faadc9d87d45a7dc1e06c654/cmd/root.go
title: firewall bouncer Execute stream loop
fetched: 2026-09-05
authority: source
ref: github.com/crowdsecurity/cs-firewall-bouncer@1dd4492523e04a25faadc9d87d45a7dc1e06c654:cmd/root.go
---

Uses github.com/crowdsecurity/go-cs-bouncer StreamBouncer. Init, then Run(ctx) in an errgroup.

Decision worker: for { select ctx.Done; decisions := <-bouncer.Stream }. Nil batch continue. Else deleteDecisions then addDecisions. No fail-closed of all traffic. No flush of the set on a missed poll.

If Run returns an error, g.Wait fails, Execute returns, defer backendCleanup → backend.ShutDown.

No live mode. No lapi_failure_action.
