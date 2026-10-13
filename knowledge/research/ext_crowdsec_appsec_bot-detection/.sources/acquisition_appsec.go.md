---
url: https://github.com/crowdsecurity/crowdsec/blob/cc76dbbce40bd2e6a3ce1ba07e3c41d8b462de66/pkg/metrics/acquisition_appsec.go
title: pkg/metrics/acquisition_appsec.go challenge counters
fetched: 2026-09-05
authority: source
ref: github.com/crowdsecurity/crowdsec@cc76dbbce40bd2e6a3ce1ba07e3c41d8b462de66:pkg/metrics/acquisition_appsec.go
---

cs_appsec_challenge_accepted_total: cookies issued, kind=solved (valid submission, empty reason) or kind=granted (GrantChallengeCookie, reason=operator string).

cs_appsec_challenge_rejected_total: kind=protocol (crypto/PoW), submission (RejectSubmission), cookie (invalid incoming cookie).

cs_appsec_challenge_exempt_total: requests flagged by ExemptFromChallenge, by reason (bot kind or path class), once per request.
