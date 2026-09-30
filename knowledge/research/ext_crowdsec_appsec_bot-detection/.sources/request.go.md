---
url: https://github.com/crowdsecurity/crowdsec/blob/cc76dbbce40bd2e6a3ce1ba07e3c41d8b462de66/pkg/appsec/request.go
title: pkg/appsec/request.go NewParsedRequestFromRequest URI parse
fetched: 2026-09-30
authority: source
ref: github.com/crowdsecurity/crowdsec@cc76dbbce40bd2e6a3ce1ba07e3c41d8b462de66:pkg/appsec/request.go
---

URIHeaderName = "X-Crowdsec-Appsec-Uri". Missing header is an error.

NewParsedRequestFromRequest:
- clientURI := r.Header.Get(URIHeaderName)
- parsedURL, err := url.Parse(clientURI)
- originalHTTPRequest := r.Clone(...); originalHTTPRequest.URL = parsedURL
- ParsedRequest.URL = parsedURL; ParsedRequest.HTTPRequest = originalHTTPRequest

No other header is copied into URL.Scheme. The bouncer-to-AppSec listener request's own URL is not used for the cloned originalHTTPRequest.URL.
