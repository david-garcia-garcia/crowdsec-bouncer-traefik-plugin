# Requirement
IssueKey: 2026-09-25-bouncer-exclude-regex

## Problem
Operators cannot skip AppSec or LAPI for a host+path on a bouncing router. There is no public regex that excludes one CrowdSec leg. Upstream https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/393 is citation-only for this run's delivery card, not a second product ask.

## Current (code)
- `pkg/configuration/configuration.go` `Config` has bouncer request-policy knobs (`BouncerAppsecFailureAction`, `BouncerLapiFailureAction`, trusted IPs, and the rest of the `bouncer*` block) and no `BouncerAppsecExcludeRegex` / `BouncerLapiExcludeRegex` — not found
- `pkg/configuration/configuration.go` `New` defaults those missing fields are absent; empty string is the default for other optional bouncer strings
- `pkg/bouncer/bouncer.go` `New` copies request policy onto `Bouncer` and does not compile a path regex
- `pkg/bouncer/bouncer.go` `ServeHTTP`: trusted IPs skip LAPI and AppSec; otherwise a subscribed LAPI leg always looks up (`LookupRemediation` / `LiveLookup`); a subscribed AppSec leg always `Query`s on the pass path (`handleNextServeHTTP` / `applyAppsecServeHTTP`)
- `pkg/appsec/query.go` `newAppsecForwardRequest` sends `httpReq.Host` (port may remain) and `httpReq.URL.String()` (query may remain) to AppSec; that is listener metadata, not an exclude gate
- `pkg/lapi/identity.go` `ownership` / `pkg/appsec/session.go` `identity` do not hash bouncer exclude regexes
- `openspec/specs/core_plugin_middleware_bouncer/spec.md` request policy is trusted IPs, ban/captcha pages, whether AppSec runs on pass, LAPI failure action, Redis fail-closed, live-cache TTL — no host+path exclude
- `README.md` documents `bouncerAppsecFailureAction` / `bouncerLapiFailureAction`, not exclude regexes

## Desired
- Public config `bouncerAppsecExcludeRegex` and `bouncerLapiExcludeRegex`. Each is one string, not a list.
- The bouncer package reads them (request policy). They are not AppSec-client or LAPI-client reclaim-key knobs.
- Compile each regex once, not on every request.
- Match a normalized incoming path `{host}/path` with no scheme, no port, no query string.
- Empty setting: nothing is excluded for that leg.

## Affected
- `pkg/configuration/configuration.go` — public fields
- `pkg/bouncer/bouncer.go` — compile at `New`; skip that leg on `ServeHTTP`
- `openspec/specs/core_plugin_middleware_bouncer/spec.md` — request-policy contract
- `knowledge/devdocs/core_plugin_middleware.md` — how to use
- `README.md` — operator knobs

## Out of scope
- Upstream #393 location-list / `EXCLUDE_LOCATION` as desired behavior.
- Putting these strings on `pkg/lapi` or `pkg/appsec` reclaim identity / ownership keys.
- Changing trusted-IP skip, forced-decision headers, or failure-action enums.
- Changing what AppSec already forwards in `X-Crowdsec-Appsec-Host` / `X-Crowdsec-Appsec-Uri` except as needed to build the bouncer match string.

## Unknowns
- Invalid regex: fail `ValidateParams` / `bouncer.New`, or ignore the setting. Ticket does not say.
- Exact `{host}/path` build from `*http.Request` (which host field, path encoding, leading slash). Ticket names the form, not the Go fields.
- What LAPI exclude does in stream/alone, where the request path does not query LAPI and still consults the store. Ticket says skip “that leg.”
- Whether a match skips only the live/none `LiveLookup` or also `LookupRemediation`.
- Regex engine flags and whether the match is unanchored `MatchString`.
- Compile/validate owner: `ValidateParams` vs `bouncer.New` only.

## Tensions
- Ticket: match `{host}/path` with no port and no query. Dest AppSec already forwards `Host` and `URL.String()` that may include both (`pkg/appsec/query.go`). That is not an exclude gate.
- Ticket: the bouncer reads the knobs. Dest AppSec `Query` lives in `pkg/appsec`; a skip must happen in `pkg/bouncer` before `Query` / before LAPI lookup, not as a client-identity field.
- Upstream #393 title is AppSec-only location list. Ticket desired is two independent one-regex settings, including LAPI, and forbids adopting that list.
