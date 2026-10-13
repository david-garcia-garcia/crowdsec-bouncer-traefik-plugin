---
url: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403
title: PR 403 appsecQuery unexpected status
fetched: 2026-10-13
authority: source
ref: github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin@e0505f9824bd8d1ddf4aa68467b00407c610afe6:bouncer.go
---

Issue 402 point 2: 401 and unexpected AppSec statuses always banned; only 500 used `crowdsecAppsecFailureBlock`.

PR 403 `appsecQuery` after unreachable 502/503/504:

- 200 → allow (`nil, nil`)
- 403 → parse JSON; empty/invalid JSON errors (ban)
- default (401, 500, other) → `Error(fmt.Sprintf("appsecQuery:failure statusCode:%d", res.StatusCode))` then `crowdsecAppsecFailureBlock` (error vs `nil, nil`)

Test: `Test_appsecQuery_unauthorizedFollowsFailureBlock`.
