---
url: https://cloud.google.com/recaptcha/docs/instrument-web-pages-with-checkbox
title: Install checkbox keys (checkbox challenge) on websites | Google Cloud Fraud Defense
fetched: 2026-09-24
authority: official
---

Automatic render: put `class="g-recaptcha"` on a `div` or `span`, set `data-sitekey`, optionally `data-action`.

Script (no `render=` site key):

`https://www.google.com/recaptcha/enterprise.js`

Sample:

```
<script src="https://www.google.com/recaptcha/enterprise.js" async defer></script>
<div class="g-recaptcha" data-sitekey="KEY_ID" data-action="LOGIN"></div>
```

Explicit render: `enterprise.js?onload=...&render=explicit` then `grecaptcha.enterprise.render(...)`.

A form POST example is documented as posting a `g-recaptcha-response` POST parameter. Another example alerts `grecaptcha.enterprise.getResponse(widgetId)` (that string is the token). A `callback` / `verifyCallback` receives the response string.

Verify the assessment `action` matches the expected action you send when creating the assessment.

This page does not name `data-callback` on the automatic `g-recaptcha` div (the JS API reference does). Last updated 2026-09-18 UTC on fetch.
