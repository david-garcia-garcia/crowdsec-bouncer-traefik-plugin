## Context

See proposal.md Why. Dest has no exclude strings (`pkg/configuration/configuration.go` `bouncer*` block). `ServeHTTP` after trusted-IP skip and forced `b` always looks up when LAPI is subscribed, and `handleNextServeHTTP` always `Query`s when AppSec is subscribed. Identity owner (explore): Host is Traefik/`net/http` `req.Host`; path for matching is `req.URL.Path`. Do not calculate Host a second time. Official Go `regexp` is RE2; `MatchString` is unanchored.

## Goals / Non-Goals

**Goals:**
- Two independent one-string RE2 knobs on Config; compile at `ValidateParams` (discard) and `bouncer.New` (store).
- Skip the named leg using `{host}/path` from `req.Host` + `req.URL.Path`.
- Keep trusted-IP, forced `b`/`c`, startup block, and failure-action enums unchanged.

**Non-Goals:**
- Upstream #393 location-list / `EXCLUDE_LOCATION`.
- Hashing these strings into `pkg/lapi` ownership or `pkg/appsec` identity.
- Changing AppSec forwarded `X-Crowdsec-Appsec-Host` / `Uri`.
- Reusing `captcha.RequestDomain` (display fallback `"This site"`).
- Silent-ignore of invalid regex.
- Skipping only `LiveLookup`.

## Decisions

1. JSON keys `bouncerAppsecExcludeRegex` / `bouncerLapiExcludeRegex` on `Config`, alphabetical by json tag (`BouncerAppsecExcludeRegex` before `BouncerAppsecFailureAction`; `BouncerLapiExcludeRegex` before `BouncerLapiFailureAction`). Default empty in `configuration.New`. Alternative: a list of locations — rejected; Desired is one string each; Out of scope for #393's list.
2. One owner `configuration.CompileExcludeRegex(s string) (*regexp.Regexp, error)`: trim; empty → `(nil, nil)`; else `regexp.Compile`. `ValidateParams` returns the error and discards the value. `bouncer.New` stores two fields (`appsecExcludeRegex`, `lapiExcludeRegex`; nil = off). Alternative: compile only in `bouncer.New` — rejected; constructor gate is `ValidateParams` so `plugin.New` fails before `lapi.Prepare`. Alternative: put `*regexp.Regexp` on `Config` — rejected; Config is the Traefik public struct.
3. Match string owner in `pkg/bouncer`: `excludeMatchString(httpReq *http.Request) string`. Host = `req.Host`; if `net.SplitHostPort` succeeds, use that host (IPv6 with port loses brackets; bare `[::1]` stays as Host wrote it). Path = `req.URL.Path`; nil URL or empty Path → `/`. Concatenate. Alternative: AppSec forwarded Host/URI — rejected; port and query may remain; not this owner. Alternative: `captcha.RequestDomain` — rejected; display fallback. Alternative: `GetRemoteIP` — rejected; that owner is client address.
4. LAPI skip sits immediately after forced `b`, before the missing-subscribed-LAPI failure action and lookup. A match goes to `passOrForcedCaptcha`. AppSec skip sits in `handleNextServeHTTP` before `applyAppsecServeHTTP`. Alternative: skip only `LiveLookup` — rejected; stream/alone would still bounce from the store. Alternative: exclude before startup block — rejected; explore order; unpublished backends still 503.
5. Unanchored `MatchString`. Operators who want a full-string match write `^...$`. Case-sensitive unless the operator writes `(?i)`. No POSIX. Alternative: always anchor — rejected; Go `MatchString` contract is contains-any-match.
6. Do not hash these knobs into reclaim keys (Out of scope). Two routers on one published client MAY disagree on exclude strings.

## Risks / Trade-offs

- [Unanchored match is broader than operators coming from nginx `location` lists] → README says write `^host/path$` for a full-string match; default empty is off.
- [IPv6 `Host` with a port drops brackets after `SplitHostPort`] → document; do not re-bracket (that would be a second Host calculation).
- [Startup block still 503s excluded health paths when a subscribed backend is unpublished] → keep explore order; operators who need those paths during startup set `bouncerStartupBlock: false`.
- [Compile twice at New] → one helper; ValidateParams is the fail-closed gate; Bouncer still owns the stored value.

## Migration Plan

Empty default. Existing YAML is unchanged. Operators set one or both strings on the bouncing router. Rollback: omit the keys.

## Open Questions

None — explore assumed rows stand.
