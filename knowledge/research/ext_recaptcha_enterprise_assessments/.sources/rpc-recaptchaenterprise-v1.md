---
url: https://cloud.google.com/recaptcha/docs/reference/rpc/google.cloud.recaptchaenterprise.v1
title: Package google.cloud.recaptchaenterprise.v1 | Google Cloud Fraud Defense
fetched: 2026-09-24
authority: official
---

RiskAnalysis.score: `float`. Output only. Legitimate event score from 0.0 to 1.0 (1.0 very likely legitimate; 0.0 very likely non-legitimate).

Event proto fields: `token`, `site_key`, `user_ip_address`, `expected_action` (optional; required for Universal keys). REST JSON names are camelCase (`siteKey`, `userIpAddress`, `expectedAction`).

TokenProperties.InvalidReason `UNEXPECTED_ACTION`: comparison with `expected_action` is case-insensitive; only for POLICY_BASED_CHALLENGE keys with a score threshold higher than 0.0 and a non-empty `expected_action`.
