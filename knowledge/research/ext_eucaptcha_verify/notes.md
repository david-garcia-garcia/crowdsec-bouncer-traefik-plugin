# Verify a client token

How official Myra EU CAPTCHA `POST /v1/verify` accepts JSON and what `success` / `train` mean.

Fetched: 2026-09-24.

## Endpoint

Send a `POST` to the `/verify` endpoint at `https://api.eu-captcha.eu/v1` — that is `https://api.eu-captcha.eu/v1/verify`. No authorization header. Authentication is the `secret` field in the body. ([Verify a client token](https://docs.eu-captcha.eu/en/api/verify/), extract `.sources/verify-a-client-token.md`)

The named verify page does not print `Content-Type`. Embedding and iOS samples send `Content-Type: application/json` on that same URL. ([Embedding the widget](https://docs.eu-captcha.eu/en/getting-started/initial-setup/embed-widget/), extract `.sources/embed-widget.md`; [iOS](https://docs.eu-captcha.eu/en/integration/mobile/ios/), extract `.sources/ios.md`)

## Request JSON

The body contains these fields. Every row is `Necessary: yes`. Types are the official table’s `string`.

| JSON field | Type | Official status |
| --- | --- | --- |
| `sitekey` | `string` | Necessary. Public sitekey. |
| `secret` | `string` | Necessary. Secret that belongs to the sitekey. Stays on the server. |
| `client_ip` | `string` | Necessary. Visitor IPv4 or IPv6, not a proxy or CDN. Obtain from `X-Forwarded-For` or `X-Client-IP`. |
| `client_token` | `string` | Necessary. Token from `verify.js`, from the `eu-captcha-response` form field. Empty if the widget did not complete (for example JavaScript off). Always send the field, including with an empty value. |
| `client_user_agent` | `string` | Necessary. Visitor `User-Agent` header. Identifies the client type if no token was calculated. |

The table lists no optional fields. ([Verify a client token](https://docs.eu-captcha.eu/en/api/verify/), extract `.sources/verify-a-client-token.md`)

The OpenAPI page lists the same five JSON names for a generated `verifyClientToken` client. It names `openapi.yaml` as OpenAPI 3.1.0 for `POST /verify` and `POST /verify-credentials` on `https://api.eu-captcha.eu/v1`. That page does not publish a URL for the file. Fetches of `https://api.eu-captcha.eu/openapi.yaml` and `https://api.eu-captcha.eu/v1/openapi.yaml` returned the marketing site, not a spec. ([Client from the specification](https://docs.eu-captcha.eu/en/integration/backend/client-from-specification/), extract `.sources/client-from-the-specification.md`)

Conflict: the embed-widget sample body uses `"token": "TOKEN_FROM_THE_WIDGET"` and omits `client_ip` and `client_user_agent`. ([Embedding the widget](https://docs.eu-captcha.eu/en/getting-started/initial-setup/embed-widget/), extract `.sources/embed-widget.md`) The verify page owns the HTTP JSON names. Follow the verify page (`client_token`, all five fields necessary).

Conflict: the Java generated-client table uses camelCase `clientIp`, `clientToken`, `clientUserAgent` as Java fields. ([Java](https://docs.eu-captcha.eu/en/integration/backend/java/), extract `.sources/java.md`) That page still says the HTTP endpoint is `POST /verify` at `https://api.eu-captcha.eu/v1`. Follow the verify page for on-the-wire JSON names.

## Response JSON (HTTP 200)

| Field | Type | Official notes |
| --- | --- | --- |
| `success` | `boolean` | `true` if the token passed, otherwise `false`. Always also examine `train`, because `success` gets `true` when `train` is `true`. |
| `train` | `boolean` or `null` | `false` and `null` are the usual operation. `true` is a verification that was skipped. |
| `error-codes` | `array` | Available only with `success: false`. Names the causes of the failure. Element type is not stated. |

Examples on that page:

- Token valid: `{ "success": true, "train": false }`
- Token invalid or used before: `{ "success": false, "train": false }`
- Verification skipped, credentials incorrect: `{ "success": true, "train": true }`

([Verify a client token](https://docs.eu-captcha.eu/en/api/verify/), extract `.sources/verify-a-client-token.md`)

### How `train` is encoded

The schema type is `boolean` or `null`. Prose: `false` and `null` are usual operation; `true` is skipped. The three examples always include the `train` key as JSON `false` or `true`. The page does not show an omitted `train` key. The page does not show a JSON `null` example. ([Verify a client token](https://docs.eu-captcha.eu/en/api/verify/), extract `.sources/verify-a-client-token.md`)

Conflict: the Java response table types `train` as `Boolean` only (`true` when training mode was on) and does not mention `null`. ([Java](https://docs.eu-captcha.eu/en/integration/backend/java/), extract `.sources/java.md`) The Ruby result object types `train` as `true`, `false`, or `nil`, and says `nil` is for a network error. ([Ruby](https://docs.eu-captcha.eu/en/integration/backend/ruby/), extract `.sources/ruby.md`) Follow the verify page for HTTP JSON (`boolean` or `null`). SDK mappings are not the wire schema.

## Empty or missing `client_ip`

`client_ip` is necessary. Error code `missing-input-remoteip`: the `client_ip` field is missing or is not a string. ([Verify a client token](https://docs.eu-captcha.eu/en/api/verify/), extract `.sources/verify-a-client-token.md`)

The owner does not state what happens when `client_ip` is present as an empty string. Empty string is a string, so that case is not the `missing-input-remoteip` wording.

## Empty or missing `client_user_agent`

`client_user_agent` is necessary. It identifies the client type if no token was calculated. ([Verify a client token](https://docs.eu-captcha.eu/en/api/verify/), extract `.sources/verify-a-client-token.md`)

The error-codes table has no code for a missing or empty `client_user_agent`. The owner does not state the HTTP status or body when the field is missing, empty, or not a string.

## HTTP statuses and error bodies

| Status | Official description |
| --- | --- |
| `200` | Result of the verification. Examine `success` and `train`. |
| `400` | Necessary fields are missing in the body, or the body is incorrect. |
| `429` | Request count exceeded. Wait the seconds in `Retry-After`, then send again. |
| `500` | Unexpected error on the server. |

One example body is given for the `400`, `429`, and `500` status codes together:

```
{ "error": "missing_field", "message": "Required field 'sitekey' is missing." }
```

The page does not give a distinct body for malformed JSON, for a missing field that is not `sitekey`, or for `429` / `500` separately. ([Verify a client token](https://docs.eu-captcha.eu/en/api/verify/), extract `.sources/verify-a-client-token.md`) The credentials endpoint reprints the same example for its `400` / `429` / `500`. ([Verify the sitekey and the secret](https://docs.eu-captcha.eu/en/api/verify-credentials/), extract `.sources/verify-credentials.md`)

`error-codes` on HTTP 200 with `success: false`:

| Value | Meaning |
| --- | --- |
| `invalid-input-secret` | Secret does not agree with the sitekey. |
| `invalid-input-sitekey` | Sitekey is unknown. |
| `invalid-input-response` | `client_token` was available but not a valid proof (incorrect, not decodable, unsolved, or empty). |
| `timeout-or-duplicate` | Token used before, or challenge expired. Each token is valid one time. |
| `missing-input-secret` | `secret` missing or not a string. |
| `missing-input-sitekey` | `sitekey` missing or not a string. |
| `missing-input-response` | `client_token` missing or not a string. An empty string counts as available and causes `invalid-input-response`. |
| `missing-input-remoteip` | `client_ip` missing or not a string. |

([Verify a client token](https://docs.eu-captcha.eu/en/api/verify/), extract `.sources/verify-a-client-token.md`)

Conflict on the same page: HTTP `400` is “necessary fields are missing or the body is incorrect”, while `missing-input-*` codes are listed under `error-codes` (available only with `success: false`, which lives on HTTP 200). The owner does not say which of those two encodings a missing field actually returns.

## `train: true` with wrong credentials or protection off

The verify page states that `success` gets `true` when `train` is `true`. A response with `train: true` means the request was not examined and each transmission counts as successful. This occurs with an unknown sitekey, with a secret that does not agree, and when the protection of the sitekey is off. It also occurs with each other malfunction of the verification. The skipped-credentials example is `{ "success": true, "train": true }`. ([Verify a client token](https://docs.eu-captcha.eu/en/api/verify/), extract `.sources/verify-a-client-token.md`)

The FAQ repeats the same pairing: `success: true` together with `train: true` for unknown sitekey, disagreeing secret, protection off, and other malfunctions. ([FAQ](https://docs.eu-captcha.eu/en/troubleshooting/faq/), extract `.sources/faq.md`)

Glossary: train mode is the condition in which the API skips verification and sets `success` permanently to `true`; the response then contains `train: true`. ([Glossary](https://docs.eu-captcha.eu/en/reference/glossary/), extract `.sources/glossary.md`)

EU CAPTCHA Protection Off: the widget does not set a challenge and requests continue without a verification. That page does not print the verify JSON. ([Configuring a sitekey](https://docs.eu-captcha.eu/en/configuration/configure-sitekey/), extract `.sources/configure-sitekey.md`)

Conflict on the same verify page: `error-codes` lists `invalid-input-secret` and `invalid-input-sitekey` as available only with `success: false`. The train paragraph, the skipped-credentials example, the FAQ, and the glossary own the claim that unknown sitekey / disagreeing secret produce HTTP 200 `{ "success": true, "train": true }`. Follow those four for credential and protection-off outcomes. The error-codes table still lists the `success: false` codes; the owner does not reconcile the two.

Conflict: the Ruby gem says `success?` already reads the train flag and gives `false` in that condition. ([Ruby](https://docs.eu-captcha.eu/en/integration/backend/ruby/), extract `.sources/ruby.md`) That is SDK result-object behaviour, not the HTTP JSON. Follow the verify page for the wire body.

The Java sample comments that training mode always allows, including when the sitekey does not exist, the secret is wrong, or the sitekey is configured with `train=true`. ([Java](https://docs.eu-captcha.eu/en/integration/backend/java/), extract `.sources/java.md`) Dashboard wording for the switch is “EU CAPTCHA Protection”, not a JSON `train=true` setting. ([Configuring a sitekey](https://docs.eu-captcha.eu/en/configuration/configure-sitekey/), extract `.sources/configure-sitekey.md`)

## Not stated by the owner pages

- JSON type of `error-codes` elements.
- HTTP result for empty-string `client_ip` (field present).
- HTTP result for missing, empty, or non-string `client_user_agent`.
- Distinct HTTP bodies for malformed JSON vs missing fields vs `429` vs `500`.
- Whether an omitted `train` key is equivalent to `false` or to JSON `null`.
- A fetchable URL for `openapi.yaml` (file is named, not linked).
- HTTP status `401` / `403` (not in the status table).

## Sources

- Official: [Verify a client token](https://docs.eu-captcha.eu/en/api/verify/)
- Official: [Verify the sitekey and the secret](https://docs.eu-captcha.eu/en/api/verify-credentials/)
- Official: [Client from the specification](https://docs.eu-captcha.eu/en/integration/backend/client-from-specification/)
- Official: [Embedding the widget](https://docs.eu-captcha.eu/en/getting-started/initial-setup/embed-widget/)
- Official: [iOS](https://docs.eu-captcha.eu/en/integration/mobile/ios/)
- Official: [FAQ](https://docs.eu-captcha.eu/en/troubleshooting/faq/)
- Official: [Glossary](https://docs.eu-captcha.eu/en/reference/glossary/)
- Official: [Configuring a sitekey](https://docs.eu-captcha.eu/en/configuration/configure-sitekey/)
- Official: [Java](https://docs.eu-captcha.eu/en/integration/backend/java/)
- Official: [Ruby](https://docs.eu-captcha.eu/en/integration/backend/ruby/)
- Extracts: `.sources/`
