---
url: https://github.com/crowdsecurity/crowdsec/blob/e20782bb3c532f0b9b9a469c0bdaa003588ec8e5/pkg/apiserver/controllers/v1/alerts.go
title: crowdsec LAPI alert intake
fetched: 2026-11-14
authority: source
ref: github.com/crowdsecurity/crowdsec@e20782bb3c532f0b9b9a469c0bdaa003588ec8e5:pkg/apiserver/controllers/v1/alerts.go
---

L128 isAllowListed: L129-131 "If we have decisions, it comes from cscli that already checked the allowlist" -> not checked. Only scope Ip or Range (L134 "Allowlist only works for IP/range"). DB error -> logged, alert processed normally.
L181-182: allowlisted -> log "alert source %s is allowlisted by %s, skipping"; alert (and so its decisions) not created.
