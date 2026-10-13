---
url: https://docs.eu-captcha.eu/en/integration/backend/java/
title: Java - Myra EU CAPTCHA Online Help
fetched: 2026-09-24
authority: official
---

Three Java clients are made from the same OpenAPI description and call the same endpoint.

Generated request fields (Java names): `sitekey`, `secret`, `clientIp`, `clientToken`, `clientUserAgent`. All necessary. `clientToken` can be empty. `clientUserAgent` is the visitor `User-Agent` header.

Generated response fields: `success` (`Boolean`) true when the challenge passed; `train` (`Boolean`) true when the training mode was on. `isTrainingMode()` reads `train`. This table does not mention JSON `null`.

HTTP endpoint: `POST /verify` at `https://api.eu-captcha.eu/v1`. No authorization header; the request identifies itself with `secret`.

Sample comment: training mode means real validation was not performed — always allow. Occurs when the sitekey does not exist, the secret is wrong, or the sitekey is configured with `train=true`.
