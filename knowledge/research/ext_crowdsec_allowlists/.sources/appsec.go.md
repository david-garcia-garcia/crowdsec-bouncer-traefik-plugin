---
url: https://github.com/crowdsecurity/crowdsec/blob/e20782bb3c532f0b9b9a469c0bdaa003588ec8e5/pkg/appsec/appsec.go
title: crowdsec AppSec remediations
fetched: 2026-11-14
authority: source
ref: github.com/crowdsecurity/crowdsec@e20782bb3c532f0b9b9a469c0bdaa003588ec8e5:pkg/appsec/appsec.go
---

L97-102: BanRemediation "ban", CaptchaRemediation "captcha", AllowRemediation "allow", ChallengeRemediation "challenge".
L1053: DefaultPassAction = AllowRemediation. "allow" is the AppSec per-request verdict / pass action, not a LAPI decision type.
