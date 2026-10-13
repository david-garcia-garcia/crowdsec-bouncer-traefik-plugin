## Why

Alone-mode `getToken` stores a CAPI token only when the login JSON has `code == 200` and a non-empty `token`. Official CrowdSec `WatcherAuthResponse` marks `code` omitempty, so a 2xx body `{"token":"fresh","expire":"later"}` fails with `getToken statusCode:0` and alone mode treats a successful CAPI login as failure.

## What Changes

- After `sendQuery` returns a 2xx CAPI login body, store `login.Token` on the stored transport when it is non-empty. Do not require JSON `code == 200`.
- Keep the existing `getToken statusCode:` error when the token is empty (including when `Code` is `0`).
- Add a committed regression in `pkg/lapi/zzz_client_http_test.go` for a 2xx body with `token` and no JSON `code`. Existing stubs that include `"code":200` stay.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_lapi_connection`: `getToken` stores a non-empty CAPI token after HTTP 2xx and does not consult JSON `code`.

## Impact

- `pkg/lapi/client_http.go` (`getToken` accept condition)
- `pkg/lapi/zzz_client_http_test.go` (regression)
- Usage already records the Token-after-2xx gotcha on `knowledge/devdocs/core_plugin_lapi_connection.md`
- Official contract stays in `knowledge/research/ext_crowdsec_watchers_login-response/`
- No **BREAKING** public JSON/YAML keys
- Out of scope: `Login` struct tags, expire parsing, CAPI host/route, 401 replay, connection drain, login-body JSON sprintf, hunt `TestHunt_GetTokenLoginBodyIsValidJSON`
