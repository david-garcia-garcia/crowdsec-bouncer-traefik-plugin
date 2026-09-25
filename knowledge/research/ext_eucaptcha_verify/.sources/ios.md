---
url: https://docs.eu-captcha.eu/en/integration/mobile/ios/
title: iOS - Myra EU CAPTCHA Online Help
fetched: 2026-09-24
authority: official
---

Server verify sample (named as sending `event.response` as `client_token`):

```
POST https://api.eu-captcha.eu/v1/verify
Content-Type: application/json

{
  "sitekey":           "EUCAPTCHA_SITE_KEY",
  "secret":            "EUCAPTCHA_SECRET_KEY",
  "client_ip":         "<client IP address>",
  "client_token":      "<token from the widget>",
  "client_user_agent": "<client user-agent>"
}
```

Response example: `{ "success": true, "train": false }`.

See Verify a client token.
