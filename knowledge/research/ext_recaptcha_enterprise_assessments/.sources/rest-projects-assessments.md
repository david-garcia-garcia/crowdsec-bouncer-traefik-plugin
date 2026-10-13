---
url: https://cloud.google.com/recaptcha/docs/reference/rest/v1/projects.assessments
title: REST Resource: projects.assessments | Google Cloud Fraud Defense
fetched: 2026-09-24
authority: official
---

Assessment JSON includes `event`, `riskAnalysis`, and `tokenProperties`.

Event JSON fields used by this finding:

- `token` (string, optional): user response token from the client-side integration.
- `siteKey` (string, optional): site key used to invoke reCAPTCHA and generate the token.
- `userIpAddress` (string, optional): IP address of the user's device for this event.
- `expectedAction` (string, optional): expected action for this event; should match the action at token generation. Required for Universal keys.

RiskAnalysis JSON: `{ "score": number, ... }`. Field `score`: number. Output only. Legitimate event score from 0.0 to 1.0 (1.0 very likely legitimate; 0.0 very likely non-legitimate).

TokenProperties JSON: `{ "valid": boolean, "invalidReason": enum, "createTime": string, "hostname": string, "action": string, ... }`.

- `valid` (boolean, output only): whether the provided user response token is valid. If false, the token is invalid because the user failed the challenge or for a reason in `invalidReason`.
- `action` (string, output only): action name provided at token generation.

InvalidReason includes `MALFORMED`, `EXPIRED`, `DUPE` (already seen), `MISSING`, `BROWSER_ERROR`, `KEY_MISMATCH` (token-generating key does not match `siteKey`), `DOMAIN_MISMATCH`.

`UNEXPECTED_ACTION`: action at token generation differed from `expectedAction`. Comparison is case-insensitive. Returned only when all of: site key is `POLICY_BASED_CHALLENGE`; action score threshold higher than 0.0; a non-empty `expectedAction` was provided.
