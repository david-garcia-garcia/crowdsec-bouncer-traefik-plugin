## Why

Alone-mode `getToken` builds the CAPI `v2/watchers/login` body with `fmt.Sprintf`. A quote, backslash, or newline in `machine_id`, `password`, or a scenario produces a body that is not valid JSON, so a legal CAPI credential cannot obtain a token.

## What Changes

- Replace the sprintf template in `getToken` with `json.Marshal` of an unexported request struct tagged `machine_id`, `password`, `scenarios`. Do not interpolate. A marshal failure returns a wrapped error and does not POST a fallback template.
- Posted fields after JSON decode MUST equal the configured `Client` strings, including quote, backslash, and newline.
- Encode `c.crowdsecScenarios` as-is (`null` if nil, `[]` if empty). Do not keep sprintf’s `[""]` for an empty list.
- Add `TestGetToken_LoginBodyIsValidJSON` in `pkg/lapi/zzz_client_http_test.go`. Bound to this defect only.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_lapi_query-round-trip`: the CAPI login POST body is JSON-marshaled from the stored `Client` credential fields so any legal credential yields a decodable body.

## Impact

- `pkg/lapi/client_http.go` (`getToken` body build only)
- `pkg/lapi/zzz_client_http_test.go` (one new test next to `TestGetToken_UnauthorizedLoginDoesNotRecurse`)
- `openspec/specs/core_plugin_lapi_query-round-trip/spec.md` (one added requirement)
- No public JSON/YAML key changes. `sendQuery` headers, renewal, drain, error wrapping, CAPI host, login route, and token storage stay as they are.
- **Behavior change:** a nil or empty scenario list now marshals as `null` or `[]`, not sprintf’s `[""]`. Credentials that already contain JSON metacharacters start working.
- Out of scope: accepting a 2xx login body that has a token but omits JSON `code`; `Content-Type`; `SetEscapeHTML(false)`; CAPI v3 `machine_id` length/pattern checks; importing the off-tree hunt file.
