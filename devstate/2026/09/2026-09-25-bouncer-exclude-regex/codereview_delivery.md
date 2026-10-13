# Delivery

## Motivation

Operators bounce a Traefik router through CrowdSec LAPI and AppSec. Request policy already has trusted client IPs (skip the whole plugin), a forced decision header, and per-leg failure actions. It has no public regex that excludes one CrowdSec leg for a host+path.

A bouncing router that also serves a probe at host `example.com` path `/health` still consults LAPI (stream/alone store, live/none lookup, missing-LAPI and stream-unhealthy failure) and still AppSec-queries on the pass path. AppSec already forwards Host and URI as listener metadata; that is not a skip. Trusted IPs skip both legs, so the only workaround is to trust the client and drop LAPI and AppSec together. There is no way to skip only AppSec or only LAPI on that path while still bouncing the rest of the router.

https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/393 is citation only for this card, not a second product ask.

Left alone, probe and static paths on a bouncing router keep paying both CrowdSec legs, or the operator has to disable bouncing for those clients entirely.

Priority: P2 — real operator pain, with a workaround (trusted IPs skip both legs)

## Implementation

Two additive Config strings `bouncerAppsecExcludeRegex` and `bouncerLapiExcludeRegex` (empty after trim is off). `ValidateParams` compiles a non-empty trimmed string as Go RE2 and fails `plugin.New` with a nil handler before LAPI open. `bouncer.New` compiles again and stores two `*regexp.Regexp` (nil is off). ServeHTTP matches unanchored `MatchString` against host + `://` + path with the leading slash removed once: `req.Host` after `net.SplitHostPort` when that succeeds, then literal `://`, then `req.URL.Path` with one leading `/` stripped (`example.com://health`; root `example.com://`; not `example.com/health` and not `example.com:///health`). After trusted IPs and forced `b`, a LAPI match skips the whole LAPI remediation path and continues at `passOrForcedCaptcha` (AppSec may still run; forced `c` still applies). An AppSec match in `handleNextServeHTTP` skips Query and calls next. The strings stay off LAPI ownership and AppSec identity.

## What this changes
**Operators.** Set `bouncerAppsecExcludeRegex` and/or `bouncerLapiExcludeRegex` on the bouncing router: a RE2 match against `host://path` (`example.com://health`, root `example.com://`) skips that CrowdSec leg; empty is off; invalid pattern fails New; write `^...$` to anchor; exclude does not override trusted IPs, forced `b`, or startup block.
**Admin users.** None.
**Developers.** Public Config JSON keys and exported `CompileExcludeRegex`; match string is port-stripped Host + `://` + decoded Path with one leading slash removed; exclude strings are not in LAPI ownership or AppSec identity.
**End users.** None.
