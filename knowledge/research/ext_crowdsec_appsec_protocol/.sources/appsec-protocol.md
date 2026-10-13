---
url: https://docs.crowdsec.net/docs/appsec/protocol
title: WAF / Bouncer Communication Protocol
fetched: 2026-10-07
authority: official
---

Section is for authors of a remediation component (or in-app integration), not operators.

Required extra headers on the forwarded request: X-Crowdsec-Appsec-Ip, X-Crowdsec-Appsec-Uri, X-Crowdsec-Appsec-Host, X-Crowdsec-Appsec-Verb, X-Crowdsec-Appsec-Api-Key, X-Crowdsec-Appsec-User-Agent, X-Crowdsec-Appsec-Http-Version.

Quoted description for X-Crowdsec-Appsec-Http-Version: "The HTTP version used by the original HTTP request (in integer form `10`, `11`, ...)".

The worked example (POST /login HTTP/1.1 forwarded to AppSec) does not include X-Crowdsec-Appsec-Http-Version. The page does not mention ProtoMajor, ProtoMinor, r.Proto, or "20".

Plus original HTTP headers and body. Forward via GET. If the original HTTP request contains a body, send POST to AppSec.

Response codes:

- 200 — request allowed. Body `{"action" : "allow"}`.
- 403 — one or more AppSec rules triggered. Body `{"action" : "ban", "http_status": 403}`, `{"action" : "captcha", "http_status": 403}`, or `{"action" : "challenge", ...}`. Bouncer applies the action and the http_status to the client.
- 500 — error in the AppSec component. Body null. Remediation component must support APPSEC_FAILURE_ACTION.
- 401 — remediation component not authenticated. Body null. Must use the same API key generated to pull LAPI.

Bot detection: 403 with action challenge. See challenge protocol.
