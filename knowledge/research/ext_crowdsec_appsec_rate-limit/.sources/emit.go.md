---
url: https://github.com/crowdsecurity/crowdsec/blob/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c/pkg/appsec/emit.go
title: pkg/appsec/emit.go alert and event emission
fetched: 2026-11-14
authority: source
ref: github.com/crowdsecurity/crowdsec@3d369d64eb3e9ba770ed39aedc83ffd3170aef4c:pkg/appsec/emit.go
---

`NewAppsecOverflow(alert, hookVars)`: `Type = APPSEC`, `Process = true`, `Overflow.Sources[ip]`, `Overflow.APIAlerts = [alert]`, `Overflow.Alert = alert`.

`EmitAlertAndEvent` comment: "The alert goes first: it is complete and short-circuits straight to LAPI, while the log event still has to travel the pipeline".
