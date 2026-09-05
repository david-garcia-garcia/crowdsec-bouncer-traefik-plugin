---
url: https://github.com/crowdsecurity/crowdsec/blob/cc76dbbce40bd2e6a3ce1ba07e3c41d8b462de66/pkg/appsec/cookie/cookie.go
title: pkg/appsec/cookie/cookie.go Set-Cookie rendering
fetched: 2026-09-05
authority: source
ref: github.com/crowdsecurity/crowdsec@cc76dbbce40bd2e6a3ce1ba07e3c41d8b462de66:pkg/appsec/cookie/cookie.go
---

AppsecCookie.String() formats a Set-Cookie compatible string via net/http.Cookie. Defaults: Path /, SameSite Lax. HttpOnly/Secure only if set on the builder. GenerateResponse serializes each UserHTTPCookies entry with String() into user_cookies []string.
