---
url: https://github.com/crowdsecurity/hub/blob/31d852a3737c12ee095bee18ebc2942fb6707e8d/collections/crowdsecurity/appsec-bot-challenge.yaml
title: hub collections appsec-bot-challenge (and strict/permissive)
fetched: 2026-09-05
authority: source
ref: github.com/crowdsecurity/hub@31d852a3737c12ee095bee18ebc2942fb6707e8d:collections/crowdsecurity/appsec-bot-challenge.yaml
---

crowdsecurity/appsec-bot-challenge: default balanced bundle, reject submissions scoring >= 75. Pulls collections appsec-bot-challenge-scoring, -good-bots, -exclude-paths; appsec-config appsec-bot-challenge-scoring-balanced; scenarios too-many-requests and too-many-submissions.

crowdsecurity/appsec-bot-challenge-strict: same blocks, scoring-strict, >= 45.

crowdsecurity/appsec-bot-challenge-permissive: same blocks, scoring-permissive, >= 100.

Landed via crowdsecurity/hub#1826 (merged 2026-08-31).
