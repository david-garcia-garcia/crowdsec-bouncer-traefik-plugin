---
url: https://crowdsecurity.github.io/capi/v3/swagger.yaml
title: prod-capi-v3 swagger LoginRequest
fetched: 2026-09-18
authority: official
---

host api.crowdsec.net, basePath /v3, version 2023-01-23T11:16:39Z.
POST /watchers/login consumes application/json, body LoginRequest, 200 LoginResponse.
LoginRequest required: machine_id, password. Properties: password (string), machine_id (string, minLength 48, maxLength 48, pattern ^[a-zA-Z0-9]+$), scenarios (array of strings, "all scenarios installed"). No other properties.
LoginResponse properties: code (integer), expire (string), token (string).
RegisterRequest (POST /watchers, not login) required machine_id + password only; no scenarios, no registration_token.
