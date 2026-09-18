# CAPI watchers login

What CrowdSec CAPI accepts on `POST /watchers/login`, which JSON fields the published CAPI and LAPI models name, and how the official CrowdSec JWT client encodes that body.

Fetched: 2026-09-18. CAPI swagger: [prod-capi-v3](https://crowdsecurity.github.io/capi/v3/swagger.yaml) (`2023-01-23T11:16:39Z`). Engine pin for the official client and LAPI model: `github.com/crowdsecurity/crowdsec@fc1677ba`.

This worktree POSTs `v2/watchers/login` from `getToken` (`pkg/lapi/client_http.go`). That path and host are **not** the owner of the login schema; they are compared at the end.

## Route

Published CAPI swagger: `POST /watchers/login` on host `api.crowdsec.net`, basePath `/v3`, consumes `application/json`. Body `$ref` `LoginRequest`. Success `LoginResponse`. Owner: [CAPI v3 swagger](https://crowdsecurity.github.io/capi/v3/swagger.yaml). Extract: `.sources/capi-v3-swagger.yaml.md`

LAPI swagger (same three request fields, different path prefix): `POST /watchers/login` on `/v1`, body `$ref` `WatcherAuthRequest`. Owner: [localapi_swagger.yaml](https://github.com/crowdsecurity/crowdsec/blob/fc1677ba/pkg/models/localapi_swagger.yaml). Extract: `.sources/localapi_swagger.yaml.md`

Official JWT client POSTs `{URL}{VersionPrefix}/watchers/login` with `Content-Type: application/json`. Owner: [auth_jwt.go](https://github.com/crowdsecurity/crowdsec/blob/fc1677ba/pkg/apiclient/auth_jwt.go). Extract: `.sources/auth_jwt.go.md`

Official docs: the Security Engine sends the list of enabled scenarios during the CAPI login process (community blocklist matching). Owner: [Central API intro](https://docs.crowdsec.net/docs/central_api/intro). Extract: `.sources/central_api_intro.md`

## Request fields

CAPI `LoginRequest` properties (only these three):

| Field | Required | Type |
| --- | --- | --- |
| `machine_id` | yes | string (CAPI v3 also documents minLength/maxLength 48 and `^[a-zA-Z0-9]+$`) |
| `password` | yes | string |
| `scenarios` | no | array of strings ("all scenarios installed") |

Owner: [CAPI v3 swagger LoginRequest](https://crowdsecurity.github.io/capi/v3/swagger.yaml). Extract: `.sources/capi-v3-swagger.yaml.md`

LAPI `WatcherAuthRequest` properties (only these three): `machine_id` (required string), `password` (required string, format password), `scenarios` (optional array of strings, "the list of scenarios enabled on the watcher"). Generated Go: `MachineID *string`, `Password *strfmt.Password`, `Scenarios []string` with those JSON tags; no other JSON fields. Owners: [localapi_swagger.yaml](https://github.com/crowdsecurity/crowdsec/blob/fc1677ba/pkg/models/localapi_swagger.yaml); [watcher_auth_request.go](https://github.com/crowdsecurity/crowdsec/blob/fc1677ba/pkg/models/watcher_auth_request.go). Extracts: `.sources/localapi_swagger.yaml.md`, `.sources/watcher_auth_request.go.md`

There is **no** extra login-body field on either published model (no `registration_token` on login; that field is on `WatcherRegistrationRequest` / CAPI `RegisterRequest` only).

## Official client encoding

`refreshJwtToken` builds `models.WatcherAuthRequest{MachineID, Password, Scenarios}` and encodes it with `json.NewEncoder(buf); enc.SetEscapeHTML(false); enc.Encode(auth)`. It does **not** interpolate strings into a JSON template. Owner: [auth_jwt.go](https://github.com/crowdsecurity/crowdsec/blob/fc1677ba/pkg/apiclient/auth_jwt.go). Extract: `.sources/auth_jwt.go.md`

`Encode` writes a trailing newline. `SetEscapeHTML(false)` keeps `&`, `<`, `>` as those bytes instead of `\u0026` / `\u003c` / `\u003e`. A standard JSON decoder still recovers the original string either way.

## Response fields (not this ticket's ask)

CAPI `LoginResponse` and LAPI `WatcherAuthResponse`: `code` (integer), `expire` (string), `token` (string). Owner: [CAPI v3 swagger](https://crowdsecurity.github.io/capi/v3/swagger.yaml); [localapi_swagger.yaml](https://github.com/crowdsecurity/crowdsec/blob/fc1677ba/pkg/models/localapi_swagger.yaml)

## This worktree (not CAPI owner)

`getToken` POSTs `v2/watchers/login` (constant `crowdsecCapiLoginRoute`) on `c.crowdsecHost` (alone mode sets `api.crowdsec.net`). The body is `fmt.Sprintf` of `machine_id`, `password`, and `strings.Join` of `crowdsecScenarios`. `sendQuery` does not set `Content-Type`. Path: `pkg/lapi/client_http.go`. Ticket out of scope: do not change the login route or `sendQuery` headers.
