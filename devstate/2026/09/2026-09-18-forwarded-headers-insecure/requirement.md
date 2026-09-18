# Requirement
IssueKey: 2026-09-18-forwarded-headers-insecure

## Problem
An operator behind a CDN cannot tell this plugin that Traefik already chose the client address. `ForwardedHeadersTrustedIPs` both gates the socket peer and skips hops inside the header, so a catch-all passes the gate then treats the header value as a trusted hop and falls back to `RemoteAddr` with no log.

## Current (code)
- `GetRemoteIP` splits `req.RemoteAddr`, then honors the custom header only when the peer is in `PoolStrategy.Checker`. `pkg/ip/checker.go`
- `PoolStrategy.getIP` walks the header right-to-left and returns the first hop not in the pool; every hop trusted or empty header returns empty. `pkg/ip/checker.go`
- `bouncer.New` copies `config.ForwardedHeadersCustomName` onto `forwardedCustomHeader` with no rewrite. `pkg/bouncer/bouncer.go`
- `ServeHTTP` calls `GetRemoteIP(httpReq, b.serverPoolStrategy, b.forwardedCustomHeader)` (three args). Nil parse remediates as `plugin:tech_trustipfail`. `pkg/bouncer/bouncer.go`
- Config has `ForwardedHeadersCustomName` then `DecisionScopeHeaders` then `ForwardedHeadersTrustedIPs`. No `ForwardedHeadersInsecure`. `New()` defaults the custom name to `X-Forwarded-For` and the list to empty. `pkg/configuration/configuration.go`
- Default-path scenarios live in `openspec/specs/core_plugin_ip_radix-lookup/spec.md`. Unit cases live in `pkg/ip/zzz_checker_test.go`.
- `knowledge/devdocs/core_plugin_ip.md` Language for GetRemoteIP has no insecure exception. Dest Gotchas end at the family catch-all note; the “no defer-to-Traefik” gotcha is not on `origin/master`.
- `knowledge/research/ext_traefik_forwardedheaders_x-real-ip/notes.md` is not on `origin/master`.

## Desired
- Add `ForwardedHeadersInsecure bool` with tag `json:"forwardedHeadersInsecure,omitempty"` between `ForwardedHeadersCustomName` and `ForwardedHeadersTrustedIPs`. Default `false` in `New()`.
- Flag off: today’s `GetRemoteIP` outcomes unchanged, including a new catch-all regression case.
- Flag on: after `SplitHostPort`, do not call `getIP` or the checker; trim the whole header; empty/whitespace falls back to `RemoteAddr` host; bare IP returns parse; anything else returns the raw string with nil `net.IP`. Bad CIDR still fails `validateParamsIPs`. `ClientTrustedIPs` still applies.
- When the flag is on and the custom name is still `X-Forwarded-For`, `bouncer.New` uses `X-Real-Ip` and emits one `log.Info` naming that header. Any other name is used as written.
- Signature `GetRemoteIP(..., insecure bool)`. No new `ValidateParams` rejection.
- Amend the radix-lookup spec, `knowledge/devdocs/core_plugin_ip.md`, the `GetRemoteIP` comment, README forwarded-headers entries, and tests listed in the ticket.

## Affected
- `pkg/ip/checker.go`, `pkg/ip/zzz_checker_test.go`
- `pkg/configuration/configuration.go`, `pkg/configuration/zzz_configuration_test.go`
- `pkg/bouncer/bouncer.go`, `pkg/bouncer/zzz_bouncer_test.go`
- `openspec/specs/core_plugin_ip_radix-lookup/spec.md`
- `knowledge/devdocs/core_plugin_ip.md`
- `README.md` (forwarded-headers option entries only)

## Out of scope
- Captcha, AppSec, cache, LAPI, reclaim
- Other `README.md` regions and the caller worktree’s uncommitted README / devdoc edits
- Fixing the pre-existing `nestif` in `pkg/configuration/configuration.go`
- Putting the flag on `PoolStrategy`

## Unknowns
- Exact Info log sentence (ticket only says it names the header actually in use).
- Whether dest should also grow the research notes file that exists only as untracked in the caller tree.

## Tensions
- Ticket line numbers treat `ForwardedHeadersCustomName` and `ForwardedHeadersTrustedIPs` as adjacent; dest has `DecisionScopeHeaders` between them. Placement stays between those two forwarded-header fields.
- Ticket cites Gotchas at `core_plugin_ip.md:57-58` that are not on dest; they exist only as uncommitted edits in the caller worktree. Dest Language entry still needs the conditional; Gotchas will state the default-path catch-all and point defer-to-Traefik at the flag.
- Ticket says correct `knowledge/research/ext_traefik_forwardedheaders_x-real-ip/notes.md` if it exists; that path is not on dest and is outside the scope fence.
