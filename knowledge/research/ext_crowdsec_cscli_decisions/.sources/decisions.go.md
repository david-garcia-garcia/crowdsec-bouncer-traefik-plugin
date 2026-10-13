---
url: https://github.com/crowdsecurity/crowdsec/blob/632274597a88a6b01ed41c0e6affca0f87ff26df/cmd/crowdsec-cli/clidecision/decisions.go
title: cmd/crowdsec-cli/clidecision/decisions.go (v1.7.8)
fetched: 2026-09-05
authority: source
ref: github.com/crowdsecurity/crowdsec@632274597a88a6b01ed41c0e6affca0f87ff26df:cmd/crowdsec-cli/clidecision/decisions.go
---

newAddCmd: --ip, --duration default "4h", --type default "ban", origin types.CscliOrigin.
newDeleteCmd Use: "delete [options]"; Aliases: []string{"remove"}.
delete --ip filters IPEquals; without --id calls client.Decisions.Delete (all matching filters).
