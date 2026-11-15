---
url: https://github.com/crowdsecurity/crowdsec/blob/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c/pkg/apiserver/controllers/v1/alerts.go
title: LAPI CreateAlert profile evaluation
fetched: 2026-11-14
authority: source
ref: github.com/crowdsecurity/crowdsec@3d369d64eb3e9ba770ed39aedc83ffd3170aef4c:pkg/apiserver/controllers/v1/alerts.go
---

Alert posted with decisions (cscli) -> stored as-is. Alert posted without decisions -> LAPI loops `c.Profiles`, `profile.EvaluateProfile(alert)`; only a matched profile appends `profileDecisions` to `alert.Decisions`. No profile matched -> the alert is stored with no decision.
