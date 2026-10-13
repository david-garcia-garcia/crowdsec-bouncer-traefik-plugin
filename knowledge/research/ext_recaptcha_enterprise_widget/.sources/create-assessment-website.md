---
url: https://cloud.google.com/recaptcha/docs/create-assessment-website
title: Create assessments for websites | Google Cloud Fraud Defense
fetched: 2026-09-24
authority: official
---

Retrieve a token as: the resolved promise from `grecaptcha.enterprise.execute()`; the `g-recaptcha-response` POST parameter on form submit; or the string argument to `data-callback` (on the `g-recaptcha` tag or the `callback` parameter of `grecaptcha.enterprise.render`).

You can access each user's token only once. For a subsequent action, or if a token expires before assessment, call `execute()` again to generate a new token.

This page does not say to omit `enterprise.js` after a refused assessment. Last updated 2026-09-18 UTC on fetch.
