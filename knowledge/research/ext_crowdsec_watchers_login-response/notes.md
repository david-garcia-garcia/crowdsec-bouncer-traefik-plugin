# Watcher login response

What CrowdSec puts in a successful `watchers/login` body, and what official `apiclient` takes from that body after HTTP 2xx.

Fetched: 2026-09-18. Engine pin: `github.com/crowdsecurity/crowdsec@fc1677baefd49581e9f9de3c0978ffd275c6338e`.

This plugin’s `getToken` is **not** the owner of CrowdSec’s contract. Compare at the end.

## Response type

`WatcherAuthResponse` is swagger-generated as “the response of a successful authentication”. Fields:

| field | Go type | JSON |
| --- | --- | --- |
| `code` | `int64` | `code,omitempty` |
| `expire` | `string` | `expire,omitempty` |
| `token` | `string` | `token,omitempty` |

`omitempty` is on every field. A success body may omit `code`. Unmarshal of an omitted `code` is Go zero (`0`). Owner: [watcher_auth_response.go](https://github.com/crowdsecurity/crowdsec/blob/fc1677baefd49581e9f9de3c0978ffd275c6338e/pkg/models/watcher_auth_response.go). Extract: `.sources/watcher_auth_response.go.md`

Swagger `WatcherAuthResponse` lists `code`, `expire`, and `token` as optional properties (no `required`). Success HTTP is documented as 200. Owner: [localapi_swagger.yaml](https://github.com/crowdsecurity/crowdsec/blob/fc1677baefd49581e9f9de3c0978ffd275c6338e/pkg/models/localapi_swagger.yaml) `WatcherAuthResponse` / `AuthenticateWatcher`.

## Official client after HTTP 2xx

`JWTTransport.refreshJwtToken` POSTs `{prefix}/watchers/login`. After `client.Do`:

1. Non-2xx (`status < 200 || status >= 300`) → `CheckResponse` and return. It does **not** read `response.Code`.
2. 2xx → decode `WatcherAuthResponse`, parse `Expire`, assign `t.Token = response.Token`.

Owner: [auth_jwt.go](https://github.com/crowdsecurity/crowdsec/blob/fc1677baefd49581e9f9de3c0978ffd275c6338e/pkg/apiclient/auth_jwt.go). Extract: `.sources/auth_jwt.go.md`

`AuthService.AuthenticateWatcher` likewise decodes the body through `client.Do` and returns it; it does not require `Code == 200`. Owner: [auth_service.go](https://github.com/crowdsecurity/crowdsec/blob/fc1677baefd49581e9f9de3c0978ffd275c6338e/pkg/apiclient/auth_service.go).

## CAPI vs LAPI route

The generated model and swagger live under LAPI. Official JWT transport uses the same type for CAPI refresh: `POST {URL}{VersionPrefix}/watchers/login`. This plugin’s alone mode uses `v2/watchers/login` on `api.crowdsec.net`. Same response type; this pin does not include a captured live CAPI body.

## This worktree (not CrowdSec owner)

`getToken` unmarshals `Login` (`json:"code"` with no `omitempty`) and stores the token only when `login.Code == 200 && len(login.Token) > 0`. `sendQuery` already rejected non-2xx before that decode. A 2xx body `{"token":"fresh","expire":"later"}` therefore yields `Code == 0` and `getToken statusCode:0`. Path: `pkg/lapi/client_http.go`.

## References

- Source: `github.com/crowdsecurity/crowdsec@fc1677baefd49581e9f9de3c0978ffd275c6338e` paths above
- Extracts: `.sources/`
