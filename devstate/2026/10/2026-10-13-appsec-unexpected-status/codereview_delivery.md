# Delivery

## Motivation

CrowdSec AppSec answers HTTP 401 when the bouncer key is rejected, and also when AppSec cannot reach LAPI to validate a key it has not cached yet. The challenge protocol says that status, like 500, uses the component's configured AppSec failure behaviour.

This fork already mapped HTTP 500 and unreachable 502/503/504 onto `bouncerAppsecFailureAction`. A bare 401 still became Query error `appsecQuery statusCode:401`, and the bouncer banned the visitor at Debug regardless of passthrough. An AppSec restart during a LAPI outage therefore banned every client even when the operator set passthrough.

Priority: P2 — real operator pain with a limited blast radius (only AppSec 401/unexpected, default action remains ban)

## Implementation

Query still parses a JSON `action` first. After `interpretAppsecBody` errors, HTTP 403 stays fail-closed. Any other leftover status (401, 418, …) logs `appsecQuery:failure` at Error with attr `statusCode` and calls `resultForFailureAction`. Passthrough returns allow so the bouncer calls next; ban keeps `appsecQuery statusCode:<n>`; captcha returns `ErrFailureCaptcha`. 500 and 502/503/504 paths are untouched. Community PR 403's bool/default branch was not copied.

## What this changes
**Operators.** `bouncerAppsecFailureAction: passthrough` now allows the request when AppSec answers 401 or another unexpected status, instead of banning; watch Error `appsecQuery:failure` with `statusCode`.
**Admin users.** None.
**Developers.** Query treats 401/unexpected like 500 for FailureAction; empty 403 still errors; do not assume every non-200 is a ban.
**End users.** Visitors are no longer banned solely because AppSec returned 401 while the operator chose passthrough.
