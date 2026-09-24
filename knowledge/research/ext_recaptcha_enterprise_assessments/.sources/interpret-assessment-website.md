---
url: https://cloud.google.com/recaptcha/docs/interpret-assessment-website
title: Interpret assessments for websites | Google Cloud Fraud Defense
fetched: 2026-09-24
authority: official
---

After the backend submits the token, you receive an assessment as JSON. Fields used here:

- `valid`: whether the user response token is valid. When `valid = false`, the reason is in `invalidReason`. `valid = false` can also mean the user failed a challenge or there is a `siteKey` mismatch.
- `action`: user interaction that triggered verification (from `execute()`).
- `expectedAction`: expected action you specified when creating the assessment.
- `score`: risk level; higher score is lower risk.

Sample assessment JSON includes `tokenProperties.valid` (boolean), `tokenProperties.action`, `tokenProperties.invalidReason`, `riskAnalysis.score`, and `event.expectedAction`.

Verify that `action` matches `expectedAction`. A mismatch indicates an attacker attempting to falsify actions. This page does not say the comparison is case-sensitive or case-insensitive.

Score: 11 levels from 0.0 to 1.0. 1.0 is low risk / very likely legitimate; 0.0 is high risk / might be fraudulent. Before a billing-account security review, only 0.1, 0.3, 0.7, and 0.9 are available.

The sample writes `"score":"SCORE"` as a placeholder. The REST schema (other owner) types `score` as JSON number.

This page also documents a classic `siteverify` response shape (`success`, `score`, `action`). That is a different method, not `projects.assessments.create`.

This page does not print HTTP status codes. Last updated 2026-09-18 UTC on fetch.
