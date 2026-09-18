---
url: https://github.com/crowdsecurity/crowdsec/blob/fc1677baefd49581e9f9de3c0978ffd275c6338e/pkg/apiclient/auth_service.go
title: AuthService.AuthenticateWatcher
fetched: 2026-09-18
authority: source
ref: github.com/crowdsecurity/crowdsec@fc1677baefd49581e9f9de3c0978ffd275c6338e:pkg/apiclient/auth_service.go
---

AuthenticateWatcher POSTs `{URLPrefix}/watchers/login` and decodes WatcherAuthResponse via client.Do.
Returns the decoded body. Does not require authResp.Code == 200.
