---
url: https://github.com/crowdsecurity/cs-firewall-bouncer/blob/a09363eebbd5ba90e8aea205728bf26194d11bf2/pkg/cfg/config.go
title: cs-firewall-bouncer BouncerConfig
fetched: 2026-11-14
authority: source
ref: github.com/crowdsecurity/cs-firewall-bouncer@a09363eebbd5ba90e8aea205728bf26194d11bf2:pkg/cfg/config.go
---

L60: SupportedDecisionsTypes []string `yaml:"supported_decisions_types"`.
L109-110: if len(config.SupportedDecisionsTypes) == 0 { config.SupportedDecisionsTypes = []string{"ban"} }.
No fallback / remediation_fallback field.
