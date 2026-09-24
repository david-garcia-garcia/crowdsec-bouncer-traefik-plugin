---
url: https://cloud.google.com/recaptcha/docs/create-assessment-website
title: Create assessments for websites | Google Cloud Fraud Defense
fetched: 2026-09-24
authority: official
---

For checkbox, score, or Universal keys, the backend submits the token to the assessment endpoint. reCAPTCHA reports the token's validity and score.

Retrieve a token as: the resolved promise from `grecaptcha.enterprise.execute()`; the `g-recaptcha-response` POST parameter; or the string argument to `data-callback` / `grecaptcha.enterprise.render` `callback`.

You can access each user's token only once. For a later action, or if a token expires before assessment, call `execute()` again.

`userIpAddress` is recommended (from the HTTP request or `X-Forwarded-For` behind a proxy), not required.

REST with an API key (the only API-key form on this page):

`POST https://recaptchaenterprise.googleapis.com/v1/projects/PROJECT_ID/assessments?key=API_KEY`

`API_KEY` is described as the API key associated with the current project.

Request JSON body used in the official sample:

```
{
  "event": {
    "token": "TOKEN",
    "siteKey": "KEY_ID",
    "userAgent": "USER_AGENT",
    "userIpAddress": "USER_IP_ADDRESS",
    "ja3": "JA3",
    "expectedAction": "USER_ACTION"
  }
}
```

`USER_ACTION` is the action passed to `grecaptcha.enterprise.execute()`.

Successful sample response includes `tokenProperties.valid`, `tokenProperties.action`, `tokenProperties.hostname`, `tokenProperties.createTime`, `riskAnalysis.score`, `riskAnalysis.reasons`, echoed `event`, and `name`.

Language-library samples: if `tokenProperties.valid` is false, print `invalidReason` and return. They treat that as a completed CreateAssessment result, not a transport failure. After `valid` is true, they compare `tokenProperties.action` to the expected action string (C# uses `!=`; Go uses `==`).

This page does not mention `X-Goog-Api-Key`. It does not print an HTTP status code for invalid tokens or bad API keys.
