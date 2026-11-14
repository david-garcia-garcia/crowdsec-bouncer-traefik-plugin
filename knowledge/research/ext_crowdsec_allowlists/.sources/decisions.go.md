---
url: https://github.com/crowdsecurity/crowdsec/blob/e20782bb3c532f0b9b9a469c0bdaa003588ec8e5/cmd/crowdsec-cli/clidecision/decisions.go
title: cscli decisions add
fetched: 2026-11-14
authority: source
ref: github.com/crowdsecurity/crowdsec@e20782bb3c532f0b9b9a469c0bdaa003588ec8e5:cmd/crowdsec-cli/clidecision/decisions.go
---

L301-306: scope ip/range and not --bypass-allowlist -> CheckIfAllowlistedWithReason; allowlisted -> error "%s is allowlisted by item %s, use --bypass-allowlist to add the decision anyway".
L394: --type/-t default "ban", help "Decision type (ie. ban,captcha,throttle)". L396: --bypass-allowlist/-B "Add decision even if value is in allowlist".
Type is any string; no "whitelist"/"allow" listed.
