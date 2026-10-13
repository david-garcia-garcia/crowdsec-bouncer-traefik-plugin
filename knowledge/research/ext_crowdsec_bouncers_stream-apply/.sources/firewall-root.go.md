---
url: https://github.com/crowdsecurity/cs-firewall-bouncer/blob/20bd97a219259190229261b601e9f722178ac40d/cmd/root.go
title: firewall bouncer stream apply loop
fetched: 2026-09-18
authority: source
ref: github.com/crowdsecurity/cs-firewall-bouncer@20bd97a219259190229261b601e9f722178ac40d:cmd/root.go
---

Stream worker: for { decisions := <-bouncer.Stream }. Nil batch continue.
Else: deleteDecisions(backend, decisions.Deleted, config) then addDecisions(backend, decisions.New, config).

deleteDecisions: for each supported type, backend.Delete(d). If any deleted, backend.Commit().
addDecisions: for each supported type, backend.Add(d). If any added, backend.Commit().

Deletes are committed before adds start. Same *decision.Value in both lists is removed then inserted.
Uses go-cs-bouncer StreamBouncer for the channel only; apply order is this file.
