---
url: https://github.com/crowdsecurity/cs-firewall-bouncer/blob/20bd97a219259190229261b601e9f722178ac40d/pkg/pf/pf.go
title: pf Commit deleted then added
fetched: 2026-09-18
authority: source
ref: github.com/crowdsecurity/cs-firewall-bouncer@20bd97a219259190229261b601e9f722178ac40d:pkg/pf/pf.go
---

pf.Commit: defer reset; commitDeletedDecisions(); return commitAddedDecisions().
Add appends decisionsToAdd. Delete appends decisionsToDelete.
Same deleted-then-added order as nftables.
