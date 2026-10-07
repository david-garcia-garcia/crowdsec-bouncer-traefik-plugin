---
url: https://github.com/crowdsecurity/crowdsec/blob/3d5c4d9b127091e9063b9b5eb785372a599a4435/pkg/appsec/request.go
title: pkg/appsec/request.go applyHTTPVersion
fetched: 2026-10-07
authority: source
ref: github.com/crowdsecurity/crowdsec@3d5c4d9b127091e9063b9b5eb785372a599a4435:pkg/appsec/request.go
---

HTTPVersionHeaderName = "X-Crowdsec-Appsec-Http-Version".

Comment on applyHTTPVersion: parses the 2-character HTTP version header (e.g. "11" for HTTP/1.1, "20" for HTTP/2) and updates r.Proto / r.ProtoMajor / r.ProtoMinor. Malformed values are logged and ignored.

applyHTTPVersion: len(version) must be 2; both bytes ASCII digits. ProtoMajor = version[0]-'0'; ProtoMinor = version[1]-'0'. If major==2 and minor==0, r.Proto = "HTTP/2"; else r.Proto = "HTTP/" + major + "." + minor.

NewParsedRequestFromRequest: if Header.Get(HTTPVersionHeaderName) is non-empty, call applyHTTPVersion; else logger.Debugf("missing '%s' header", HTTPVersionHeaderName). Missing IP/URI/Verb headers return an error; missing HTTP version does not.

The header is then deleted with the other X-Crowdsec-Appsec-* forwarded headers before Coraza sees the request. ParsedRequest.Proto is copied from r.Proto after that apply.
