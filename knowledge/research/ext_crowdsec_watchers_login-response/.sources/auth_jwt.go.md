---
url: https://github.com/crowdsecurity/crowdsec/blob/fc1677baefd49581e9f9de3c0978ffd275c6338e/pkg/apiclient/auth_jwt.go
title: JWTTransport.refreshJwtToken watcher login
fetched: 2026-09-18
authority: source
ref: github.com/crowdsecurity/crowdsec@fc1677baefd49581e9f9de3c0978ffd275c6338e:pkg/apiclient/auth_jwt.go
---

POST `{URL}{VersionPrefix}/watchers/login` with WatcherAuthRequest (machine_id, password, scenarios).
After client.Do: if StatusCode < 200 or >= 300, CheckResponse and return. No read of response.Code.
On 2xx: json-decode WatcherAuthResponse, parse Expire, set t.Token = response.Token.
Empty Expire fails at UnmarshalText. Empty Token is stored as empty; no Code==200 check.
