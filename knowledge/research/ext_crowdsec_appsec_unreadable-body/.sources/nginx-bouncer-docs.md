---
url: https://docs.crowdsec.net/u/bouncers/nginx
title: NGINX IP Blocking, CAPTCHA & WAF with CrowdSec
fetched: 2026-09-06
authority: official
---

Sample config includes APPSEC_DROP_UNREADABLE_BODY=false.

Warning: Due to limitations in the underlying library, by default the body of any HTTP2/HTTP3 request without a Content-Length will not be analyzed. To avoid potential bypasses of the WAF, set APPSEC_DROP_UNREADABLE_BODY to true to drop any request whose body cannot be inspected.

Configuration Reference — APPSEC_DROP_UNREADABLE_BODY:
- bool, default false
- If the bouncer cannot read the request body (eg, HTTP2 without Content-Length header), drop or not the request without forwarding it to the WAF.
- false (default): request evaluated by WAF without body content.
- true: request blocked directly by nginx.
