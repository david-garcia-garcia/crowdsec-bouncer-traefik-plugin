---
url: https://github.com/crowdsecurity/crowdsec/blob/909b5157986a2b2c2163300fdaef5ed01289f7d2/pkg/apiserver/controllers/controller.go
title: POST /usage-metrics route
fetched: 2026-09-05
authority: source
ref: github.com/crowdsecurity/crowdsec@909b5157986a2b2c2163300fdaef5ed01289f7d2:pkg/apiserver/controllers/controller.go
---

eitherAuth.POST("/usage-metrics", UsageMetrics). Auth: X-Api-Key → API key; Authorization → JWT; User-Agent crowdsec/ → JWT; else API key.
