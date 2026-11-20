# Delivery

## Motivation

The reclaim table already binds three groups: LAPI, AppSec, and captcha. `plugin.go` names `legLAPI`, `legAppSec`, `legCaptcha` only. There is no ModSecurity group, no `pkg/modsecurity`, and no `modsec*` keys. Operators who want OWASP CRS inspect still load `david-garcia-garcia/traefik-modsecurity` as a second Traefik plugin. README Traefik Security still lists that sibling as a separate middleware.

AppSec `Query` applies `bouncerAppsecFailureAction` on every unreachable, 5xx, or unreadable miss. The packaged default is `ban`. There is no admission gate, so a down AppSec listener keeps banning every later request. `passthrough` already exists as a per-request workaround without back-off. AppSec Sleep/Wake are reclaim hooks, not request skip.

Left alone, a down AppSec takes ingress down for the life of the outage unless someone remembers `passthrough`, and CRS stays a second plugin with a second config surface for the same allow-or-block inspect job. The source plugin's real Pester families (allow, CRS path-traversal block, body-size, deny-verbs, failMode, backoff) are also absent from this tree's real e2e.

Priority: P2 — real operator pain with a workaround and limited blast radius

## Implementation

A fourth reclaim group `modsec` copies the captcha-leg own-vs-bounce pattern: `modsecEnabled` Opens and publishes; `bouncerEnabled` plus a non-empty `modsecInstanceName` Watches; claim failure rolls this group back with the others. The new reclaim Client copies the inbound request to absolute `modsecUrl`, classifies sidecar 2xx as allow, copies 3xx/4xx as the visitor block without following redirects, and treats 5xx or transport as a WAF miss. Per-router `bouncerModsecFailMode` (`open` default, `close` empty HTTP 502) sits on the Bouncer; utilities `backendbackoff.Gate` sits on the shared Client (ModSec period default 0, so the gate is off until set). ServeHTTP runs ModSec after AppSec; trusted clients skip LAPI, AppSec, and ModSec; `bypassModsec` skips only CRS, and `bypass` now skips all three inspect legs. Deny-verbs and `modsecBodyLimit` (omitted 8 MiB, `0` unlimited) run before the gate.

The same Gate is imported onto the AppSec Client. Omitted `appsecUnhealthyBackOffPeriodSecs` is 30, so after the trip later requests skip AppSec and do not apply FailureAction; admitted misses still use `bouncerAppsecFailureAction` (default `ban` unchanged). Those knobs join the AppSec ownership key. An AppSec gate skip continues to ModSec when that leg is subscribed. README documents the ModSec leg and drops the sibling-plugin listing. Real e2e adds Pester domain `modsec` with an inspect-only Apache CRS sidecar and the mapped source families.

## What this changes
**Operators.** New own-axis `modsecEnabled`, `modsecUrl`, `modsecInstanceName`, and per-router `bouncerModsecFailMode`; omitted AppSec backoff is 30s skip-after-trip (set `appsecUnhealthyBackOffPeriodSecs: 0` to keep per-request FailureAction). `modSecurityUrl` does not bind. `bypass` now also skips ModSec.
**Admin users.** None.
**Developers.** `bouncer.New` takes a fourth subscribe flag; reclaim group `modsec`; action token `bypassModsec` and `ActionMatch.SkipModsec`; AppSec `ErrGateSkip` means the hop was skipped and FailureAction must not run; remediation header value `ban:modsec`.
**End users.** After AppSec trips unhealthy under the new default gate, later visitors are no longer banned solely because AppSec is down. When operators enable ModSec, sidecar 3xx/4xx becomes a visitor-facing block.
