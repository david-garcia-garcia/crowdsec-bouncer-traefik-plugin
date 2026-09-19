---
url: https://developers.cloudflare.com/turnstile/get-started/server-side-validation/
title: Validate the token · Cloudflare Turnstile docs
fetched: 2026-09-18
authority: official
---

Endpoint: `POST https://challenges.cloudflare.com/turnstile/v0/siteverify`

The API accepts both `application/x-www-form-urlencoded` and `application/json` requests, but always returns JSON responses.

| Parameter | Required | Description |
| --- | --- | --- |
| secret | Yes | Your widget's secret key from the Cloudflare dashboard |
| response | Yes | The token from the client-side widget |
| remoteip | No | The visitor's IP address |
| idempotency_key | No | A UUID you generate to safely retry validation requests |

Official Form Data example appends `remoteip`. PHP sample adds `remoteip` only `if ($remoteip)`. C# sample adds it when `!string.IsNullOrEmpty(remoteip)`.

Error codes include `internal-error` — Internal error occurred — Action required: Retry the request.

Performance guidance: set reasonable timeouts; implement retry logic and handle temporary network issues; have fallback behavior for API failures; use user-friendly messaging and do not expose internal error details to users.
