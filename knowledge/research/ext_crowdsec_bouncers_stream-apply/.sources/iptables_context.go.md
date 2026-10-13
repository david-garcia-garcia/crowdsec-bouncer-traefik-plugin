---
url: https://github.com/crowdsecurity/cs-firewall-bouncer/blob/20bd97a219259190229261b601e9f722178ac40d/pkg/iptables/iptables_context.go
title: iptables/ipset commit del then add
fetched: 2026-09-18
authority: source
ref: github.com/crowdsecurity/cs-firewall-bouncer@20bd97a219259190229261b601e9f722178ac40d:pkg/iptables/iptables_context.go
---

ipTablesContext.add appends to toAdd. delete appends to toDel.
commit() writes an ipset restore file: first a "del <set> <value> -exist" line per toDel, then add lines per toAdd. Value is *decision.Value (IP or CIDR).
After write, toAdd and toDel are nilled.
Stream loop commits a delete-only batch then an add-only batch; even a mixed Commit would still del before add.
