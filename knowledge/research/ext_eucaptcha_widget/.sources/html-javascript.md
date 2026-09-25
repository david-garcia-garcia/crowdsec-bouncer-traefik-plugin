---
url: https://docs.eu-captcha.eu/en/integration/frontend/html-javascript/
title: HTML and JavaScript - Myra EU CAPTCHA Online Help
fetched: 2026-09-24
authority: official
---

Script: `https://cdn.eu-captcha.eu/verify.js` with `async defer`.

Widget element in the form:

```
<div class="eu-captcha" data-sitekey="a1b2c3d4-0000-0000-0000-000000000000"></div>
```

Full form sample: ordinary fields, the `eu-captcha` div, a submit button. No hidden input in the markup.

During the transmission, the widget adds the hidden `eu-captcha-response` field with the token.

`verify.js` attributes:

- `data-sitekey` — necessary.
- `data-theme` default `"light"`.
- `data-width` default `330`.
- `data-height` default `100`.
- `data-widgetid` automatic.
- `data-autostart` default `"true"`; `"false"` delays the start of the challenge.
- `data-callback` — name of a global function that is called after the challenge passed. Default —. No arguments named.
- `data-expired-callback` — called when the token expires.
- `data-error-callback` — called when an error occurs.

npm `onComplete`: `(token: string) => void` — called with the token as soon as the challenge passed.

Window message alternative: origin `https://cdn.eu-captcha.eu`, type `euCaptchaCompleted`.
