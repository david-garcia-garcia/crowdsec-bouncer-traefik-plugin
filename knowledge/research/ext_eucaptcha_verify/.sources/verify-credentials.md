---
url: https://docs.eu-captcha.eu/en/api/verify-credentials/
title: Verify the sitekey and the secret - Myra EU CAPTCHA Online Help
fetched: 2026-09-24
authority: official
---

`POST` `/verify-credentials` at `https://api.eu-captcha.eu/v1`. Available from API version 1.1.

Statuses: `200`, `400` (necessary fields missing or body incorrect), `429` (`Retry-After`), `500`.

Error response example for `400`, `429`, and `500` (same shape as the `/verify` page):

```
{ "error": "missing_field", "message": "Required field 'sitekey' is missing." }
```

HTTP 200 body: `{ "valid": true }` or `{ "valid": false }`. This endpoint does not use a visitor token.
