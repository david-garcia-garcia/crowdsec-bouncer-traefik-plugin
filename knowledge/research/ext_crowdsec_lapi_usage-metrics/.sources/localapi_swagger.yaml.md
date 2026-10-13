---
url: https://github.com/crowdsecurity/crowdsec/blob/909b5157986a2b2c2163300fdaef5ed01289f7d2/pkg/models/localapi_swagger.yaml
title: LAPI swagger AllMetrics and /usage-metrics
fetched: 2026-09-05
authority: source
ref: github.com/crowdsecurity/crowdsec@909b5157986a2b2c2163300fdaef5ed01289f7d2:pkg/models/localapi_swagger.yaml
---

POST /usage-metrics body AllMetrics. Documented 200. Security APIKeyAuthorizer or JWTAuthorizer.
RemediationComponentsMetrics: BaseMetrics + type, name, last_pull.
BaseMetrics required: version, utc_startup_timestamp. Optional: os, metrics (array of DetailedMetrics), feature_flags ([]string, "expected to be empty for remediation components").
DetailedMetrics required: meta, items.
MetricsDetailItem required: name, value, unit (each name/unit maxLength 255). labels: MetricsLabels additionalProperties string maxLength 255 (open map).
OSversion required name+version if os present.
No enum of item names or label keys. No scenario field.
