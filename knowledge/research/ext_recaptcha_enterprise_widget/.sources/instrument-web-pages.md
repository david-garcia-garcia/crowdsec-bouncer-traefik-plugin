---
url: https://cloud.google.com/recaptcha/docs/instrument-web-pages
title: Install score-based keys on websites | Google Cloud Fraud Defense
fetched: 2026-09-24
authority: official
---

Score-based key: no challenge. Create an assessment within two minutes of token generation.

Load the script with the site key on `render`:

`https://www.google.com/recaptcha/enterprise.js?render=KEY_ID`

Boot on a user interaction:

1. Use `grecaptcha.enterprise.ready()` so `execute` runs after the library loads.
2. Call `grecaptcha.enterprise.execute('KEY_ID', {action: 'LOGIN'})` (official sample action `LOGIN`).
3. Send the resulting token to the backend.

Official sample:

```
grecaptcha.enterprise.ready(async () => {
  const token = await grecaptcha.enterprise.execute('KEY_ID', {action: 'LOGIN'});
});
```

Call `execute` on each interaction you want to protect.

HTML-button alternative still uses `class="g-recaptcha"`, `data-sitekey`, `data-callback`, `data-action`. When that button submits a form, `g-recaptcha-response` holds the token.

The `action` from `execute()` is returned on the assessment; verify it matches `expectedAction`.

This page does not say to omit the script after a refused score. Last updated 2026-09-18 UTC on fetch.
