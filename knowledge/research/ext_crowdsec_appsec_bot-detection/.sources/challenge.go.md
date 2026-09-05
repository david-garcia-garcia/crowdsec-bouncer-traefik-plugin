---
url: https://github.com/crowdsecurity/crowdsec/blob/cc76dbbce40bd2e6a3ce1ba07e3c41d8b462de66/pkg/appsec/challenge/challenge.go
title: pkg/appsec/challenge/challenge.go paths and cookie name
fetched: 2026-09-05
authority: source
ref: github.com/crowdsecurity/crowdsec@cc76dbbce40bd2e6a3ce1ba07e3c41d8b462de66:pkg/appsec/challenge/challenge.go
---

Bouncers MUST forward these paths to WAF unmodified (comment). Constants:
- ChallengeJSPath = /crowdsec-internal/challenge/challenge.js (defined; v1.8.0 dispatcher does not serve it)
- ChallengeSubmitPath = /crowdsec-internal/challenge/submit
- ChallengePowWorkerPath = /crowdsec-internal/challenge/pow-worker.js
- ChallengeFPScannerPath = /crowdsec-internal/challenge/fpscanner.js

ChallengeCookieName = __crowdsec_challenge
defaultCookieTTL = 12h
DefaultChallengeCSP allows inline script/style and blob workers.
