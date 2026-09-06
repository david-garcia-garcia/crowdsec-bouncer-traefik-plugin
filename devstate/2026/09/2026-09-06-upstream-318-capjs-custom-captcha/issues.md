# Issues

- [ ] note large  extra custom-captcha verify fields/headers (none today) → optional extra body/header map
  Why: ticket asked for more control over verification request generation; this change ships JSON vs form only. CapJS Standalone needs only `secret` and `response`. Other providers may need more.
- [ ] note large  Wicketkeeper example documents urlencoded `secret`/`response` → Wicketkeeper `/v0/siteverify` JSON `token`/`nonce`/`response`
  Why: official Wicketkeeper server README is not reCAPTCHA-shaped. This change does not retarget the example; CapJS is the ask.
