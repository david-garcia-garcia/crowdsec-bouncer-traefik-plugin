---
url: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/04d928872df12bdb9d953b2d92948e0b89692d6a/pkg/configuration/configuration.go
title: configuration.go defaults
fetched: 2026-09-05
authority: source
ref: github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin@04d928872df12bdb9d953b2d92948e0b89692d6a:pkg/configuration/configuration.go
---

New() defaults:

CrowdsecMode: live
CrowdsecAppsecFailureBlock: true
CrowdsecAppsecUnreachableBlock: true
CrowdsecAppsecUnreadableBodyBlock: true  (README at this commit says false)
UpdateMaxFailure: 0
StreamStartupBlock: true
HTTPTimeoutSeconds: 10
RedisCacheUnreachableBlock: true

Two AppSec bools, not an enum. No LAPI failure-action field.
