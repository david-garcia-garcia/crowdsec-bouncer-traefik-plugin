---
url: https://github.com/crowdsecurity/lua-cs-bouncer/blob/4aad1df/lib/crowdsec.lua
title: lua-cs-bouncer AppSec captcha handling
fetched: 2026-11-14
authority: source
ref: github.com/crowdsecurity/lua-cs-bouncer@4aad1df:lib/crowdsec.lua
---

AppSecCheck (around line 734): 200 → remediation allow; 403 → JSON decode, remediation = response.action, status_code = response.http_status (else 403); `challenge` keeps user_body_content / headers / cookies.

Before querying AppSec (around lines 826-880): when captcha is configured and the client has a pending captcha state (VERIFY_STATE) in the shared cache, the request is checked as a captcha submission first. Comment: "the form is posted back to the URI that triggered the captcha, so letting the appsec judge it again would just return the same remediation and we would never get a chance to validate the answer." A valid answer stores VALIDATED_STATE for CAPTCHA_EXPIRATION "for both sources: an appsec captcha is triggered by the request itself, so without this grace period the redirect below would hit the very rule that asked for the captcha and we would serve it again, forever."

State is tagged with its source; "a captcha solved for a LAPI decision does not grant a free pass on the appsec (and the other way around)". A LAPI allow drops only a LAPI-sourced captcha state.

Fallback (around line 905): if remediation is captcha and captcha is not usable → FALLBACK_REMEDIATION; any remediation other than captcha, ban, challenge → FALLBACK_REMEDIATION.

Apply: ban → ban page; challenge with response data → relay, without → ban; captcha (configured, not /favicon.ico) → captcha page unless validated for the same source.
