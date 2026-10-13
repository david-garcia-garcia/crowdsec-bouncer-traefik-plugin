---
url: https://github.com/crowdsecurity/cs-firewall-bouncer/blob/1dd4492523e04a25faadc9d87d45a7dc1e06c654/pkg/iptables/iptables_context.go
title: firewall iptables lists origin
fetched: 2026-09-05
authority: source
ref: github.com/crowdsecurity/cs-firewall-bouncer@1dd4492523e04a25faadc9d87d45a7dc1e06c654:pkg/iptables/iptables_context.go
---

Comment: lists origin uses scenario as the list name to build a custom origin for per-list metrics; other origins' scenarios are too noisy. origin == "lists" → origin + ":" + scenario.
