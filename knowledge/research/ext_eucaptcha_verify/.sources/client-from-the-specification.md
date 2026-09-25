---
url: https://docs.eu-captcha.eu/en/integration/backend/client-from-specification/
title: Client from the specification - Myra EU CAPTCHA Online Help
fetched: 2026-09-24
authority: official
---

Generate a client from `openapi.yaml` according to OpenAPI 3.1.0. It describes `POST /verify` and `POST /verify-credentials` on `https://api.eu-captcha.eu/v1`.

Requirements table: “The `openapi.yaml` file is available”. This page does not give a download URL or permalink.

Generator command uses a local `-i openapi.yaml`. Myra generates its own clients with `openapi-generator-cli` version 7.18.0.

`POST /verify` operation name: `verifyClientToken`. Request JSON field names listed:

- `sitekey`
- `secret`
- `client_ip`
- `client_token`
- `client_user_agent`

Always also read `train` in the answer. If it has the `true` value, no verification occurred.
