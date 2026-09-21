# Requirement
IssueKey: 2026-09-18-capi-login-json-escape

## Problem
`getToken` builds the CAPI `v2/watchers/login` body with `fmt.Sprintf`. A quote, backslash, or newline in `machine_id`, `password`, or a scenario produces a body that is not valid JSON, so alone mode cannot obtain a token.

## Current (code)
- `getToken` interpolates `c.crowdsecMachineID`, `c.crowdsecPassword`, and `strings.Join(c.crowdsecScenarios, `","`)` into a JSON-looking string. `pkg/lapi/client_http.go`
- `New` copies those three fields from `config.LapiCapiMachineID`, `LapiCapiPassword`, `LapiCapiScenarios`. `pkg/lapi/client.go` `pkg/configuration/configuration.go`
- Login POST uses that byte slice; `sendQuery(..., false)` so a 401 does not recurse. `pkg/lapi/client_http.go`
- Response is unmarshaled into `Login` (`code`, `token`, `expire`). Token is stored only when `login.Code == http.StatusOK` and `token` is non-empty. `pkg/lapi/client_http.go`
- Existing getToken tests use plain `machine` / `password` / `scenario` and do not assert the posted body is JSON. `pkg/lapi/zzz_client_http_test.go`
- Cited proof `TestHunt_GetTokenLoginBodyIsValidJSON` is not found on dest. It exists only off-tree (`wt-hunt-lapi/pkg/lapi/zzz_hunt_lapi_test.go`).

## Desired
- Marshal a struct with JSON tags `machine_id`, `password`, `scenarios` via `encoding/json` so any legal CAPI credential yields a decodable body.
- Posted fields must equal the configured strings (including quotes, backslashes, and scenario list members).
- Add a regression test for that body. Bound to this defect only.

## Affected
- `pkg/lapi/client_http.go` (`getToken` body build)
- `pkg/lapi/zzz_client_http_test.go` (or a sibling `zzz_` test in `pkg/lapi`)
- `openspec/specs/core_plugin_lapi_query-round-trip/spec.md` and/or `knowledge/devdocs/core_plugin_lapi_query-round-trip.md` only if propose decides the login body encoding belongs there (they currently cover renewal, drain, and error text, not body encoding)

## Out of scope
- Accepting a 2xx login body that has a token but omits JSON `code` (sibling hunt; `getToken` still requires `code == 200`)
- Changing `sendQuery` renewal, drain, or error wrapping
- Changing CAPI host, login route, or token storage on `transport`
- Config validation, file-backed CAPI secrets, stream poll, live lookup
- Importing or committing the off-tree hunt file as a whole
- Other hunt defects (stream apply order, LAPI path join, LapiUpdateMaxFailure)

## Unknowns
- Official CAPI login schema extras beyond the three fields already posted (ticket names those three only).
- Whether the regression test should keep the `TestHunt_` name or a package-local name in `zzz_client_http_test.go`.

## Tensions
- Ticket line numbers `165-170` match dest `fad36a1` `getToken` sprintf.
- Cited FAIL test is not on dest; current behavior is still visible in `client_http.go`.
- `encoding/json` is already imported in `client_http.go` for the login response.
- Query-round-trip spec/usage do not mention login-body encoding; this ticket does not add a new product ask beyond a valid JSON body.
