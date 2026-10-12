# Requirement
IssueKey: 2026-10-12-modsecurity-leg

## Problem
Absorb https://github.com/david-garcia-garcia/traefik-modsecurity (Apache-2.0, same owner) into this Traefik plugin as a new ModSecurity leg beside LAPI, AppSec, and captcha. The caller treats ModSecurity as the same kind of per-request WAF as AppSec and therefore pluggable. Copy that plugin's back-off strategy onto AppSec so a down AppSec does not take ingress down. Bring as much of the source repo's real e2e coverage as possible. README.md must document the whole project's capabilities and configuration, including how to configure the ModSecurity leg. Not a replacement for AppSec. Not a second Traefik plugin.

## Current (code)
- Legs in this tree are LAPI, AppSec, and captcha only. `plugin.go` names `legLAPI`, `legAppSec`, `legCaptcha`. `openOwnedLeg` / `claimOwnedLeg` switch on those three. There is no ModSecurity group.
- `pkg/bouncer/bouncer.go` New takes subscribe flags for those three legs. Receive paths are `pkg/bouncer/bouncer_leg_lapi.go`, `pkg/bouncer/bouncer_leg_appsec.go`, `pkg/bouncer/bouncer_leg_captcha.go`. No `bouncer_leg_modsecurity.go`.
- `pkg/modsecurity` not found. No `modsec*` config keys in `pkg/configuration/configuration.go`.
- AppSec is an independent reclaim client (`pkg/appsec/client.go`) that forwards the request (`pkg/appsec/query.go` Query) and remediates from the verdict (`pkg/bouncer/bouncer.go` applyAppsecServeHTTP).
- When AppSec is unreachable, nil, or returns 5xx, Query applies `FailureAction` per request (`pkg/appsec/query.go` resultForFailureAction). Default `bouncerAppsecFailureAction` is `ban` (`pkg/configuration/configuration.go` CreateConfig). `passthrough` and `captcha` exist. There is no back-off that stops calling a down AppSec. `pkg/appsec/session.go` Sleep/Wake are reclaim hooks, not request back-off.
- README.md documents AppSec, LAPI, captcha, failure actions, and the full config surface. `README.md` "Traefik Security" still lists `david-garcia-garcia/traefik-modsecurity` as a separate sibling plugin. No ModSecurity-leg configuration section.
- Real AppSec e2e lives in `tests/e2e/real/appsec.Tests.ps1`. No ModSecurity e2e suite in `tests/e2e/real`. Coverage from the source traefik-modsecurity repo is not in this tree.
- This repo's LICENSE is Apache-2.0.

## Desired
- A new ModSecurity leg alongside LAPI, AppSec, and captcha, by absorbing traefik-modsecurity into this project.
- Not a replacement for AppSec. Not a second Traefik plugin.
- Copy the back-off strategy from the modsec plugin onto AppSec so a down AppSec does not take ingress down.
- Bring in as much real e2e coverage from the original traefik-modsecurity project as possible.
- README.md states capabilities and configuration of the project as a whole, including how to configure the ModSecurity leg.

## Affected
- `plugin.go` leg open/claim/watch
- `pkg/bouncer/bouncer.go` and leg files
- `pkg/appsec/query.go` AppSec failure path
- `pkg/configuration/configuration.go`
- `README.md`
- `tests/e2e/real`
- `pkg/modsecurity` not found

## Out of scope
- Replacing or removing AppSec
- Shipping ModSecurity as a second Traefik plugin
- Changing LAPI or captcha product behavior except as required to add a fourth leg
- Geoblock, ratelimit, or other sibling middlewares listed in README.md

## Unknowns
- Exact back-off algorithm, knobs, and pass/fail behavior in traefik-modsecurity (vendor; explore/research).
- How much of that repo's real e2e exists and what of it maps onto this project's Pester stack.
- Whether "exactly the same as appsec" holds at the HTTP and config layer, or only at the "forward request, allow or block" layer.
- How a fourth leg binds (instance name, reclaim, subscribe) once designed. Dest already has the three-leg model; the mapping is not specified in the ask.
- Whether AppSec default `ban` stays, with back-off as an extra layer, or whether back-off implies a different down-path.

## Tensions
- README.md advertises traefik-modsecurity as a separate Traefik plugin; the ask is to absorb it so this project is not a second plugin.
- Default AppSec failure action is `ban` (`pkg/configuration/configuration.go`), which blocks the request when AppSec is down. The ask is that a down AppSec must not take ingress down. Existing `passthrough` already lets the request through, without back-off.
- "What modsec does is exactly the same as appsec" is the caller's claim; this tree has not verified the source plugin.
