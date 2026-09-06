---
url: https://github.com/a-ve/wicketkeeper/blob/main/server/README.md
title: Wicketkeeper server README
fetched: 2026-09-06
authority: official
---

POST /v0/siteverify

Headers: Content-Type: application/json

Request body JSON:
{
  "token": "<challenge_jwt>",
  "nonce": "<nonce>",
  "response": "<sha256_hash>"
}

Not reCAPTCHA-shaped: uses token+nonce+response, not secret+response.

Success response:
{ "success": true, "token": "<success_jwt>", "challenge": "...", "timestamp": "..." }

Contrast: Wicketkeeper siteverify verifies PoW solution JWT, not a shared secret + widget token pair.
