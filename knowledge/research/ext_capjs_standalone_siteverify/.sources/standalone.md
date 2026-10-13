---
url: https://trycap.dev/guide/standalone/
title: Cap Standalone
fetched: 2026-09-18
authority: official
---

Cap Standalone is the recommended self-hosted Cap backend. Docker image `tiago2/cap:latest`. Dashboard login is `ADMIN_KEY`. Create a site key and note site key + secret key.

Widget `data-cap-api-endpoint` is `https://<instance_url>/<site_key>/`. Example uses `<cap-widget>`.

Server-side verify: POST to `/siteverify` with JSON body:

```
curl "https://<instance_url>/<site_key>/siteverify" \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{ "secret": "<key_secret>", "response": "<captcha_token>" }'
```

`key_secret` is the dashboard site secret, not `ADMIN_KEY`. `captcha_token` is the widget challenge token.

Success reply: `{ "success": true }`.

Page also says Standalone ships a siteverify API compatible with reCAPTCHA.
