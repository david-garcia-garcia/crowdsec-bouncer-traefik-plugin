---
url: https://docs.hcaptcha.com/
title: Developer Guide | hCaptcha
fetched: 2026-09-18
authority: official
---

Verify the token at `https://api.hcaptcha.com/siteverify`.

The endpoint expects a POST with account secret and the `h-captcha-response` token. Do not send JSON data: the endpoint expects a standard URL-encoded form POST.

Additionally, you should include the user's IP address for enhanced security. While not strictly required, providing the IP address helps improve verification accuracy. For Enterprise customers, this also enables risk scores.

Example:

```
curl https://api.hcaptcha.com/siteverify \
  -X POST \
  -d "secret=YOUR-SECRET&remoteip=CLIENT-IP&response=CLIENT-RESPONSE"
```

CLIENT-IP is the client's IP address. While `remoteip` is not strictly required, providing it helps improve verification accuracy.

| POST Parameter | Description |
| --- | --- |
| secret | Required. Your account secret key. |
| response | Required. The verification token you received when the user completed the challenge on your site. |
| remoteip | Recommended. The user's IP address. |
| sitekey | Optional. The sitekey you expect to see. |

Siteverify error codes include:

- `missing-remoteip` — The remoteip parameter is missing.
- `invalid-remoteip` — The remoteip parameter is not a valid IP address or blinded value.
