---
url: https://github.com/crowdsecurity/cs-firewall-bouncer/blob/a09363eebbd5ba90e8aea205728bf26194d11bf2/cmd/root.go
title: cs-firewall-bouncer stream apply
fetched: 2026-11-14
authority: source
ref: github.com/crowdsecurity/cs-firewall-bouncer@a09363eebbd5ba90e8aea205728bf26194d11bf2:cmd/root.go
---

L64 deleteDecisions: for each decision
  L68 if !slices.Contains(config.SupportedDecisionsTypes, strings.ToLower(*d.Type)) {
  L69   log.Debugf("decisions for ip '%s' will not be deleted because its type is '%s'", *d.Value, *d.Type)
        continue }
  then backend.Delete(d).

L104 addDecisions: for each decision
  L108 same SupportedDecisionsTypes check (lower-cased type)
  L109   log.Debugf("decisions for ip '%s' will not be added because its type is '%s'", *d.Value, *d.Type)
        continue
  then backend.Add(d).

Same filter on both halves. Unsupported types are skipped (Debug log only); there is no fallback remediation.
