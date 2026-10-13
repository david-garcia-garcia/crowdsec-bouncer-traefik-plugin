---
url: https://docs.crowdsec.net/docs/next/contributing/specs/bouncer_appsec_specs.md
title: Specifications for Remediation Component and AppSec Capabilities
fetched: 2026-09-05
authority: official
---

AppSec disabled by default; activable if url exists (configurable field appsec_url). Default endpoint http://127.0.0.1:7422.

Auth by API key passed in the header X-Api-Key: same param as LAPI apikey. (Conflicts with protocol page header X-Crowdsec-Appsec-Api-Key.)

Forwarding protocol: docs.crowdsec.net/docs/next/appsec/protocol/. Security engine returns the response code the remediation component should display, except codes 500 and 401 which mean forwarding or authentication failed — trigger the fallback.

AppSec forwarding is a blocking process.

Timeout 200ms, configurable field appsec_timeout.

Fallback in case of timeout or response failure (500, 401…): default passthrough (let him pass). Possible values: passthrough, ban, captcha. Configurable field appsec_failure_action.

Nginx + lua-cs-bouncer named as the complete reference implementation with AppSec.
