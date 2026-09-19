---
url: https://github.com/crowdsecurity/cs-firewall-bouncer/blob/1dd4492523e04a25faadc9d87d45a7dc1e06c654/pkg/nftables/nftables.go
title: firewall nftables lists origin hyphen
fetched: 2026-09-05
authority: source
ref: github.com/crowdsecurity/cs-firewall-bouncer@1dd4492523e04a25faadc9d87d45a7dc1e06c654:pkg/nftables/nftables.go
---

If origin == "lists", origin = origin + "-" + scenario (hyphen, not colon). Differs from iptables and lua lists: rewrite.
