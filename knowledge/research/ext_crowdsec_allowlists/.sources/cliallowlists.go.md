---
url: https://github.com/crowdsecurity/crowdsec/blob/e20782bb3c532f0b9b9a469c0bdaa003588ec8e5/cmd/crowdsec-cli/cliallowlists/allowlists.go
title: cscli allowlists add implementation
fetched: 2026-11-14
authority: source
ref: github.com/crowdsecurity/crowdsec@e20782bb3c532f0b9b9a469c0bdaa003588ec8e5:cmd/crowdsec-cli/cliallowlists/allowlists.go
---

add: db.AddToAllowlist(...), print "added %d values to allowlist %s", then L514 db.ApplyAllowlistsToExistingDecisions(ctx); L519 prints "%d decisions deleted by allowlists".
