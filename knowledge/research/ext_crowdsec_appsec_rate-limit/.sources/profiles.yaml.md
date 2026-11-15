---
url: https://github.com/crowdsecurity/crowdsec/blob/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c/config/profiles.yaml
title: config/profiles.yaml default profiles
fetched: 2026-11-14
authority: source
ref: github.com/crowdsecurity/crowdsec@3d369d64eb3e9ba770ed39aedc83ffd3170aef4c:config/profiles.yaml
---

`default_ip_remediation`: filter `Alert.Remediation == true && Alert.GetScope() == "Ip"` -> `ban` 4h, `on_success: break`.
`default_range_remediation`: same filter on `Range` scope.

Scenario alerts get `Remediation = true` only when the scenario carries label `remediation: true` (`pkg/leakybucket/overflows.go` at the same commit: `if v, ok := leaky.Factory.Spec.Labels["remediation"]; ok && v == true { newApiAlert.Remediation = true }`).
