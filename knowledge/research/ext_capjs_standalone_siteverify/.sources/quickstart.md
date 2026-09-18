---
url: https://trycap.dev/guide/
title: Cap Quickstart
fetched: 2026-09-18
authority: official
---

`/siteverify` is described as compatible with reCAPTCHA's API (change one URL). Official verify examples are still JSON:

- curl: `Content-Type: application/json` and `{"secret","response"}`
- JS `fetch`: `JSON.stringify({ secret, response })`
- Python: `requests.post(..., json={"secret","response"})`
- PHP: `json_encode(["secret","response"])`

Valid token returns `{ "success": true }`. Tokens are single-use.

Widget inside a form injects hidden `cap-token`. Token is also `e.detail.token`. Secret must be the site secret, not `ADMIN_KEY`.
