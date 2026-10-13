---
url: https://github.com/crowdsecurity/crowdsec/blob/909b5157986a2b2c2163300fdaef5ed01289f7d2/cmd/crowdsec-cli/climetrics/statbouncer.go
title: cscli metrics show bouncers aggregation
fetched: 2026-09-05
authority: source
ref: github.com/crowdsecurity/crowdsec@909b5157986a2b2c2163300fdaef5ed01289f7d2:cmd/crowdsec-cli/climetrics/statbouncer.go
---

extractRawMetrics reads item.Labels["ip_type"] and item.Labels["origin"] only. Aggregates over time then ip_type then origin. isGauge: name == "active_decisions" || strings.HasSuffix(name, "_gauge"). Empty origin skipped in table body, still in Total. formatMetricOrigin annotates CAPI/cscli/crowdsec. knownPlurals: byte, packet, ip.
