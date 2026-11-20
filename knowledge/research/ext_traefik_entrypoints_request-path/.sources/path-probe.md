---
url: https://hub.docker.com/_/traefik
title: Traefik path probe with this plugin loaded (measured)
fetched: 2026-11-20
authority: inference
---

Measured 2026-11-20 on the images `traefik:v3.7.11` and `traefik:v3.7` (reported version 3.7.19), with `traefik/whoami` as the backend and this plugin loaded as a local plugin.

Setup: file provider, one entry point. Router `Host(plugin.test)` runs the plugin with `lapiEnabled: false` and one action rule `{name: api, path: "^/api/", action: [ban]}`. Router `Host(plain.test)` has no middleware. Requests sent with `curl --path-as-is`. "rule" is whether the plugin answered `403` with `ban:rules` (the path regex matched what the plugin received). "backend" is the request line whoami printed on the router without the plugin.

Default entry point options:

| Raw path sent | rule, 3.7.11 | backend, 3.7.11 | rule, 3.7.19 | backend, 3.7.19 |
|---|---|---|---|---|
| `/api/x` | match | `/api/x` | match | `/api/x` |
| `/api/../other` | no match | `/other` | no match | `/other` |
| `/api/%2e%2e/other` | no match | `/other` | no match | `/other` |
| `/api/.%2e/other` | no match | `/other` | no match | `/other` |
| `/api/..\other` | no match | `/other` | no match | `/other` |
| `/other/../api/x` | match | `/api/x` | match | `/api/x` |
| `/api//x` | match | `/api/x` | match | `/api/x` |
| `/api/x%20y` | match | `/api/x%20y` | match | `/api/x%20y` |
| `/api/..;/other` | match | `/api/..;/other` | no match | `/other` |
| `/api/..;x/other` | match | `/api/..;x/other` | no match | `/other` |
| `/api/%2E%2E;/other` | match | `/api/..;/other` | no match | `/other` |
| `/api/..%2Fother` | match | `/api/..%2Fother` | match | `/api/..%2Fother` |
| `/api/%2e%2e%2Fother` | match | `/api/..%2Fother` | match | `/api/..%2Fother` |
| `/api/..%3B/other` | match | `/api/..%3B/other` | match | `/api/..%3B/other` |
| `/api/..%5Cother` | match | `/api/..%5Cother` | match | `/api/..%5Cother` |
| `/api%2Fx` | match | `/api%2Fx` | match | `/api%2Fx` |
| `/api/%252e%252e/other` | match | `/api/%252e%252e/other` | match | `/api/%252e%252e/other` |
| `/other/..%2Fapi/x` | no match | `/other/..%2Fapi/x` | no match | `/other/..%2Fapi/x` |

With `--entrypoints.web.http.encodedCharacters.allowEncodedSlash=false`, `allowEncodedBackSlash=false`, `allowEncodedSemicolon=false` and `allowEncodedPercent=false`, both versions answer `400` to every row that holds `%2F`, `%5C`, `%3B` or `%25` (`/api/..%2Fother`, `/api/%2e%2e%2Fother`, `/api/..%3B/other`, `/api/..%5Cother`, `/api%2Fx`, `/api/%252e%252e/other`, `/other/..%2Fapi/x`), on both routers. The other rows are unchanged.

Not measured: Traefik v2, HTTP/2 and HTTP/3 requests, `sanitizePath: false`, and how any particular backend reads the forwarded path.
