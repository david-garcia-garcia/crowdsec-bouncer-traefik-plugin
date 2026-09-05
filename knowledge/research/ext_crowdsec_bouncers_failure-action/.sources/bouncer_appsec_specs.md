---
url: https://docs.crowdsec.net/docs/next/contributing/specs/bouncer_appsec_specs.md
title: Specifications for Remediation Component and AppSec Capabilities
fetched: 2026-09-05
authority: official
---

Live mode GET /decisions. Timeout if LAPI doesn’t respond: default 200ms, field lapi_timeout. Fallback in case of timeout: default passthrough (let him pass). Possible values passthrough, ban, captcha. Field lapi_failure_action. Cache default 1s, field cache_expiration.

Stream mode is preferred and the default (field mode). GET /decisions/stream, startup=true then deltas. Recommended pull 10s, field stream_update_frequency. No fail-open/fail-closed for a failed poll. Store decisions in memory; prune deleted and expired TTL.

Custom remediation unknown type: field remediation_fallback, defaults ignore/ban/captcha.

AppSec: field appsec_url. Timeout 200ms, field appsec_timeout. Fallback on timeout or response failure (500, 401…): default passthrough. Possible values passthrough, ban, captcha. Field appsec_failure_action. Forwarding is blocking.

Nginx + lua-cs-bouncer named as the complete reference implementation.
