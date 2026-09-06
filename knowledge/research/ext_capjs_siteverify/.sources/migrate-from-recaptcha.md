---
url: https://trycap.dev/guide/alternatives/migrate-from-recaptcha.md
title: Migrating from reCAPTCHA to Cap
fetched: 2026-09-06
authority: official
---

reCAPTCHA verify: POST application/x-www-form-urlencoded with URLSearchParams secret + response to google.com/recaptcha/api/siteverify.

Cap verify: POST application/json JSON.stringify secret + response to own /<site-key>/siteverify.

Widget token field: cap-token instead of g-recaptcha-response.

Compatibility table reCAPTCHA vs Cap:
- Request params: reCAPTCHA secret, response, optional remoteip | Cap secret, response (remoteip ignored)
- Success field: success boolean both
- Error reporting: reCAPTCHA error-codes array | Cap error string
- Extra fields: reCAPTCHA challenge_ts, hostname, score | Cap none

Code checking only response.success works after URL and secret swap.
