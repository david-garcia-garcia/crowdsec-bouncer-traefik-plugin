---
url: https://github.com/crowdsecurity/cs-firewall-bouncer/blob/1dd4492523e04a25faadc9d87d45a7dc1e06c654/pkg/cfg/config.go
title: firewall BouncerConfig
fetched: 2026-09-05
authority: source
ref: github.com/crowdsecurity/cs-firewall-bouncer@1dd4492523e04a25faadc9d87d45a7dc1e06c654:pkg/cfg/config.go
---

BouncerConfig has Mode (ipset|iptables|nftables|pf), UpdateFrequency, API URL/key/TLS, DenyAction, no fail_open, no lapi_failure_action, no appsec fields.

Default yaml: update_frequency 10s, api_url http://127.0.0.1:8080/, deny_action DROP, supported_decisions_types ban.
