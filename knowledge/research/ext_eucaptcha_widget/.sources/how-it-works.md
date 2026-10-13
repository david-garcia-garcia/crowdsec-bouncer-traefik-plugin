---
url: https://docs.eu-captcha.eu/en/introduction/how-it-works/
title: How EU CAPTCHA works - Myra EU CAPTCHA Online Help
fetched: 2026-09-24
authority: official
---

Widget address: `https://cdn.eu-captcha.eu/verify.js`.

Verification steps:

1. Protected page loads `verify.js` from the CDN.
2. `verify.js` creates a hidden iframe and loads `check.html`.
3. `check.html` loads `check.all.js`.
4. The iframe reports the created token back to `verify.js`.
5. `verify.js` writes the token into a hidden input field named `eu-captcha-response`.
6. When the form is submitted, the token reaches the operator's server.
7. The operator's server verifies through `POST /verify`.

Solved Immediate (default): verification starts as soon as the page is loaded. Best user experience: verification can already be complete when users submit the form.

Solved Triggered: verification starts once users touch the form.
