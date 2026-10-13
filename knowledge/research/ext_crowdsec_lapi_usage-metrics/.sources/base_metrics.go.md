---
url: https://github.com/crowdsecurity/crowdsec/blob/909b5157986a2b2c2163300fdaef5ed01289f7d2/pkg/models/base_metrics.go
title: BaseMetrics feature_flags
fetched: 2026-09-05
authority: source
ref: github.com/crowdsecurity/crowdsec@909b5157986a2b2c2163300fdaef5ed01289f7d2:pkg/models/base_metrics.go
---

FeatureFlags []string `json:"feature_flags"`. Comment: expected to be empty for remediation components. Object JSON cannot unmarshal into []string.
Metrics []*DetailedMetrics `json:"metrics"` — array, not object.
