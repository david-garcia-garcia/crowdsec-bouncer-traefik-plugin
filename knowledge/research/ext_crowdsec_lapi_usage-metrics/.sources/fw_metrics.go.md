---
url: https://github.com/crowdsecurity/cs-firewall-bouncer/blob/1dd4492523e04a25faadc9d87d45a7dc1e06c654/pkg/metrics/metrics.go
title: firewall bouncer metric items
fetched: 2026-09-05
authority: source
ref: github.com/crowdsecurity/cs-firewall-bouncer@1dd4492523e04a25faadc9d87d45a7dc1e06c654:pkg/metrics/metrics.go
---

Maps prometheus gauges to usage-metrics items: active_decisions unit ip labels origin+ip_type; dropped unit byte and packet labels origin+ip_type; processed unit byte and packet labels ip_type only. MetricsUpdater appends one DetailedMetrics window onto met.Metrics (array).
