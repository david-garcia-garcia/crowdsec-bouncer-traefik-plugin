---
url: https://docs.crowdsec.net/u/bouncers/nginx
title: NGINX IP Blocking, CAPTCHA & WAF with CrowdSec
fetched: 2026-09-05
authority: official
---

Sample config: MODE=stream, REQUEST_TIMEOUT=1000, UPDATE_FREQUENCY=10, FALLBACK_REMEDIATION=ban, APPSEC_FAILURE_ACTION=passthrough (commented as default).

FALLBACK_REMEDIATION = ban | captcha. Applied if the component receives a decision with an unknown remediation. Not LAPI/AppSec unavailability.

MODE = stream | live. Reference text: “The default mode is live.” (Conflicts with the sample MODE=stream.) Stream: pull new/old decisions every UPDATE_FREQUENCY seconds. Timer triggered after the first request. Live: query LAPI per request if IP not in cache; CACHE_EXPIRATION seconds.

REQUEST_TIMEOUT: milliseconds for HTTP requests to LAPI or captcha provider. No lapi_failure_action / fail_open documented.

APPSEC_FAILURE_ACTION = passthrough | deny. Default passthrough. “Behavior when the AppSec Component return a 500. Can let the request passthrough or deny it.” Values are deny, not spec ban/captcha. No separate unreachable bool.

APPSEC_CONNECT_TIMEOUT / APPSEC_SEND_TIMEOUT / APPSEC_PROCESS_TIMEOUT for AppSec I/O. APPSEC_DROP_UNREADABLE_BODY default false.
