---
url: https://github.com/crowdsecurity/cs-firewall-bouncer/blob/20bd97a219259190229261b601e9f722178ac40d/pkg/nftables/nftables.go
title: nftables Commit deleted then added
fetched: 2026-09-18
authority: source
ref: github.com/crowdsecurity/cs-firewall-bouncer@20bd97a219259190229261b601e9f722178ac40d:pkg/nftables/nftables.go
---

nft.Commit: defer reset; commitDeletedDecisions(); return commitAddedDecisions().
Add queues decisionsToAdd. Delete queues decisionsToDelete.
A single Commit still applies deletes before adds. The stream loop also commits delete-only then add-only batches separately.
