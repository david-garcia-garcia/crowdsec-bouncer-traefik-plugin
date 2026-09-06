---
url: https://github.com/crowdsecurity/crowdsec/blob/909b5157986a2b2c2163300fdaef5ed01289f7d2/pkg/apiserver/controllers/v1/usagemetrics.go
title: UsageMetrics handler
fetched: 2026-09-05
authority: source
ref: github.com/crowdsecurity/crowdsec@909b5157986a2b2c2163300fdaef5ed01289f7d2:pkg/apiserver/controllers/v1/usagemetrics.go
---

Binds AllMetrics. 400 on bind error, 422 on Validate failure.
Bouncer from context → generated_type RC, generated_by bouncer.Name (row name, not payload name).
Exactly one remediation_components entry. Payload stored: {"type": item0.Type, "metrics": item0.Metrics}.
Then BouncerUpdateBaseMetrics(ctx, bouncer.Name, bouncer.Type, baseMetrics) — type argument is the existing row type.
Missing os filled with empty name/version pointers.
CreateMetric then Status 201 Created.
