---
url: https://github.com/crowdsecurity/crowdsec/blob/909b5157986a2b2c2163300fdaef5ed01289f7d2/pkg/apiserver/apic_metrics.go
title: CAPI usage-metrics batch
fetched: 2026-09-05
authority: source
ref: github.com/crowdsecurity/crowdsec@909b5157986a2b2c2163300fdaef5ed01289f7d2:pkg/apiserver/apic_metrics.go
---

dbPayload unmarshals only Metrics. rcBaseMetrics copies Name/Type/OS/FeatureFlags/Version from the bouncer row, then appends stored DetailedMetrics (all item labels intact). Snapshot JSON "type" is not forwarded.
