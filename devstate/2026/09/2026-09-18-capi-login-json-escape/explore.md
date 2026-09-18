# Explore
IssueKey: 2026-09-18-capi-login-json-escape

## Concepts

Alone-mode token fetch is `getToken` → `sendQuery(loginURL, loginData, false)` on `v2/watchers/login`. Dest builds `loginData` with `fmt.Sprintf` and `strings.Join(c.crowdsecScenarios, `","`)` (`pkg/lapi/client_http.go`). Those three strings already live on `Client` (`crowdsecMachineID`, `crowdsecPassword`, `crowdsecScenarios`), copied in `New` from `config.CrowdsecCapiMachineID` / `CrowdsecCapiPassword` / `CrowdsecCapiScenarios` after `Prepare` `GetVariable`. `getToken` does not reconstruct visitor address, Host, or trust hop.

```
config.CrowdsecCapi*  ──Prepare/New──►  Client fields
                                          │
                                          ▼
                         getToken sprintf body   ← dest BUG
                                          │
                                          ▼
                         sendQuery(..., false)  POST v2/watchers/login
                                          │
                                          ▼
                         json.Unmarshal → Login{code,token,expire}
```

`encoding/json` is already imported here for the **response**. `Login` is that response DTO (`code`, `token`, `expire`). A request DTO is a second type; it may sit next to `Login` because it exists only to feed `getToken`.

`core_plugin_lapi_query-round-trip` owns the exchange: one-shot `mayRenewToken`, drain, named errors. It does not mention login-body encoding. Usage is enough to call `sendQuery` / `getToken`. Language has no gap. This phase wrote no usage packet.

Official CAPI/LAPI login body is three fields only (`machine_id`, `password`, `scenarios`). Finding: `knowledge/research/ext_crowdsec_capi_watchers-login/`. Official JWT client marshals `WatcherAuthRequest` with `json.Encoder` + `SetEscapeHTML(false)` and sets `Content-Type: application/json`. This tree does neither. Ticket fences `sendQuery` headers and the login route.

No active OpenSpec change. `openspec list --json` → `changes: []`.

**Reproduced** (temp `go run` of dest sprintf, 2026-09-18, not product code):

| Input | sprintf body | `json.Unmarshal` |
| --- | --- | --- |
| plain `machine`/`password`/`scenario` | valid | ok |
| password `p"w` | `..."p"w"...` | `invalid character 'w' after object key:value pair` |
| password `p\w` | invalid escape | `invalid character 'w' in string escape code` |
| password `p\nw` | raw newline in string | `invalid character '\n' in string literal` |
| scenario `scen"ario` | split array | `invalid character 'a' after array element` |
| `scenarios == nil` | `"scenarios": [""]` | ok, but one empty string, not empty/null |

`json.Marshal` of a tagged struct recovered the original password and scenario strings on every case. Nil slice marshals as `null`; dest sprintf of nil/empty join is `[""]`.

Existing tests (`TestGetToken_UnauthorizedLoginDoesNotRecurse`, renewal replay) use plain `machine` / `password` / `scenario` and do not read the login body. Off-tree `TestHunt_GetTokenLoginBodyIsValidJSON` is not on dest.

## Decisions

- Replace the sprintf template with `json.Marshal` of an unexported request struct tagged `machine_id`, `password`, `scenarios`. Do not reuse `Login` (that is the response). Do not interpolate. If Marshal fails, return a wrapped error and do not POST a fallback template.
- Post only those three fields. Official CAPI `LoginRequest` and LAPI `WatcherAuthRequest` have no extras. Do not add `registration_token` or CAPI v3 `machine_id` length/pattern checks (config validation is out of scope).
- Posted fields after JSON decode must equal the configured Client strings, including quote, backslash, and newline. `json.Marshal` HTML-escaping `&<>` is acceptable: a decoder still yields the original string. Do not add `SetEscapeHTML(false)` this ticket (official client nicety, not required for a decodable body).
- Encode `c.crowdsecScenarios` as-is (`null` if nil, `[]` if empty). Do not keep sprintf’s `[""]` for an empty list. Do not invent a default scenario.
- Keep `sendQuery(..., false)`, token write on the stored transport, `code == 200` + non-empty token, CAPI host, and `v2/watchers/login`. Do not set `Content-Type` this ticket.
- Regression test in `pkg/lapi/zzz_client_http_test.go` as `TestGetToken_LoginBodyIsValidJSON` (package-local, next to `TestGetToken_UnauthorizedLoginDoesNotRecurse`). Stub captures the login POST body, unmarshals it, and compares the three fields to Client values that contain `"`, `\`, and a newline. Do not import or commit the off-tree hunt file. Do not keep the `TestHunt_` name.
- Propose change name: `capi-login-json-escape`. Fold a login-body requirement into `core_plugin_lapi_query-round-trip` (same `getToken` file; no new spec leaf). Usage gotcha only if propose/devdocsimpact says the packet is incomplete after that fold.

## Open questions

- Q: Who already owns `machine_id`, `password`, and `scenarios` for the login body?
  Decision: resolved — `configuration` after `GetVariable` / `New` copy onto `Client`. `getToken` only encodes those fields. Do not re-read files or reconstruct identity.
  By: explore

- Q: Does official CAPI login require fields beyond `machine_id`, `password`, `scenarios`?
  Decision: resolved — no. CAPI v3 `LoginRequest` and LAPI `WatcherAuthRequest` name only those three. `registration_token` is register, not login. See `knowledge/research/ext_crowdsec_capi_watchers-login/`.
  By: explore

- Q: Should the regression test keep the off-tree `TestHunt_` name?
  Decision: resolved — no. Use `TestGetToken_LoginBodyIsValidJSON` in `zzz_client_http_test.go`.
  By: explore

- Q: `json.Marshal` or official-client `Encoder` + `SetEscapeHTML(false)`?
  Decision: assumed — `json.Marshal` (already used in this package for session/identity/metrics). Posted fields are compared after decode. Do not add an Encoder this ticket.
  By: explore

- Q: How should an empty or nil scenario list be encoded?
  Decision: assumed — marshal the Client slice as-is (`null` / `[]`). Do not emit sprintf’s `[""]`. Do not add `omitempty` unless propose finds CAPI rejects `null`.
  By: explore

- Q: Does login-body encoding belong on `core_plugin_lapi_query-round-trip`?
  Decision: assumed — yes, one added requirement on that spec/usage pair. Do not open a new leaf. Propose writes the delta.
  By: explore

- Q: Should this ticket set `Content-Type: application/json` on the login POST?
  Decision: assumed — no. Official client sets it; `sendQuery` does not. Ticket fences `sendQuery` header/renewal changes. Alone mode already works for plain credentials without it.
  By: explore
