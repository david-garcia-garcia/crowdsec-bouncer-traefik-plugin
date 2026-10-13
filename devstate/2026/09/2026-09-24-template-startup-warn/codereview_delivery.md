# Delivery

## Motivation

Traefik middleware `New` for the CrowdSec bouncer plugin used to fail when a captcha provider was configured but the captcha HTML file was missing or empty, so the route never came up even though ban remediation could still run with an empty body. An empty ban template path was accepted with no startup signal, so operators could deploy without a ban page and only discover it from silent 403 responses.

That mismatch blocked bouncing routers on template filesystem mistakes and hid ban-page gaps until traffic hit remediation.

Priority: P2 — real operator pain (dead route or silent empty ban) with a workaround (fix template paths before deploy).

## Implementation

Validation no longer fail-closes on captcha or ban template load in `ValidateParams`; site, secret, and gate checks stay when captcha is enabled. Each owner warns once at construction: the captcha client logs `crowdsec captcha template unavailable`, leaves `Valid` false, and returns success so existing remediation code bans captcha decisions; the bouncer logs `crowdsec bouncer ban template unavailable` and keeps a nil ban template so GET ban stays status-only. Bounce-only routers never open captcha, so unused default `/captcha.html` is not read or warned.

## What this changes
**Operators.** Watch for one-time startup WARN lines when captcha or ban template paths are empty or unreadable; the middleware still starts and captcha remediations fall back to ban with an empty body.

**Admin users.** None.

**Developers.** `ValidateParams` and `Client.New` no longer error on missing captcha templates; `Client.New` succeeds with `Valid` false instead of returning `GetTemplate` errors. Ban template load errors are warned in `bouncer.New`, not validation.

**End users.** None.
