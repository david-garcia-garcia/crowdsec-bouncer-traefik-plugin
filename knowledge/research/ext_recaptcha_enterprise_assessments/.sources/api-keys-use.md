---
url: https://cloud.google.com/docs/authentication/api-keys-use
title: Use API keys to access APIs | Authentication | Google Cloud Documentation
fetched: 2026-09-24
authority: official
---

Not all Google Cloud APIs accept API keys. Review the service docs.

Using an API key with REST: include the `x-goog-api-key` HTTP header. Official sample:

```
curl -X POST \
    -H "X-goog-api-key: API_KEY" \
    -H "Content-Type: application/json; charset=utf-8" \
    -d @request.json \
    "https://translation.googleapis.com/language/translate/v2"
```

If you cannot use the HTTP header, you can use the `key` query parameter. That form puts the key in the URL.

This page's REST examples are Translation and Cloud Natural Language, not reCAPTCHA. It does not print HTTP status codes for an invalid key. Last updated 2026-09-23 UTC on fetch.
