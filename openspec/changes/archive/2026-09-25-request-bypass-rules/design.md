## Context

See proposal.md Why. Dest has `BouncerAppsecExcludeRegex` / `BouncerLapiExcludeRegex` compiled by `CompileExcludeRegex`, matched as `host://path` in `pkg/bouncer` (`excludeMatchString`, `excludedBy`). Identity owners (explore): client address stays `ip.GetRemoteIP`; path is `req.URL.Path` as `net/http` decoded it; host is optional RE2 on the hostname of `req.Host` (port stripped). Official Go `regexp` is RE2; `MatchString` is unanchored. Nested YAML maps already decode (`bouncerDecisionScopeHeaders`). Subpackages are Yaegi-loadable; `CreateConfig` / `New` stay at module root.

## Goals / Non-Goals

**Goals:**
- Replace the two strings with two `[]httprule.Rule` lists; compile once in `httprule.New`; same ServeHTTP skip sites as dest exclude.
- Matcher package imports only stdlib so a later utilities move does not drag plugin types.
- Fail closed on invalid RE2, `!!`, `!` with no pattern, and fully empty rules; fail `plugin.New` before LAPI Open.

**Non-Goals:**
- Moving `pkg/httprule` into traefik-middleware-utilities.
- Packed `headerRegexp` strings or `target: header:Name`.
- A captcha-leg list.
- Aliases or a `host://path` converter.
- Changing trusted-IP skip, forced `b`, or startup-block 503.
- Real-stack Pester as the required e2e.

## Decisions

1. Package `pkg/httprule`. Authoring type `Rule` with json `method`, `path`, `host`, `headers`, `cookies`. Compiled `Set` with `Match(*http.Request) bool`. Alternative: `pkg/bypassrule` — rejected; ties a later utilities move to this plugin's knob. Alternative: keep match helpers on `pkg/bouncer` — rejected; Desired is its own package with no plugin imports.
2. `httprule.New([]Rule) (*Set, error)` is the compile owner. Reject invalid RE2 (path, host, method, header, cookie) and fully empty rules. Fully empty = path, host, headers, and cookies all absent AND method is any (omitted, empty after trim, or a match-everything pattern such as `.*`). A method-only or host-only rule is valid. `!` with an empty pattern and `!!` are invalid syntax, not the fully-empty case. `ValidateParams` calls `New` and wraps the error with `BouncerAppsecBypassRules` / `BouncerLapiBypassRules`. `bouncer.New` calls it again to store `*httprule.Set` (same split as dest `CompileExcludeRegex`). Alternative: compile only in `bouncer.New` — rejected; constructor gate is `ValidateParams`. Alternative: put compiled regexes on `Config` — rejected; Config is the Traefik public struct.
3. Method is Go RE2, unanchored `MatchString` on `req.Method`. Do not insert `^`/`$`, do not lowercase, do not force `(?i)`. Optional single leading `!` stripped before compile negates. Alternative: exact case-insensitive HTTP token — rejected; human correction (method is the same family as path). Go RE2 has no lookahead; `regexp.Compile` failure is the constructor error.
4. Path is unanchored `MatchString` on `req.URL.Path`. Do not use `excludeMatchString`. Alternative: keep `host://path` beside the lists — rejected; human correction replace-and-remove.
5. Headers: compile names with `textproto.CanonicalMIMEHeaderKey`; request check uses `req.Header[canonical]` (every value, not `Header.Get`). Empty pattern = present. Cookies: same shape; names case-sensitive (`net/http` cookie parse / RFC 6265). Parse Cookie once per request only when that compiled `Set` has a cookie predicate. Host: unanchored RE2 on the hostname of `req.Host` (`SplitHostPort` when that succeeds). Request loop: method, path, host, headers, cookies (AND, short-circuit). Alternative: canonicalize cookie names like headers — rejected; cookie names are not header keys. Alternative: omit host — rejected; human correction, operators must be able to filter by host.
6. Public fields `BouncerAppsecBypassRules` / `BouncerLapiBypassRules`, json tags alphabetical (`BouncerAppsecBypassRules` before `BouncerAppsecFailureAction`; `BouncerLapiBypassRules` before `BouncerLapiFailureAction`). Delete the exclude strings and `CompileExcludeRegex`. Alternative: keep old strings beside the lists — rejected; Out of scope aliases; leftover keys dropped by Traefik unused-key decode (`knowledge/research/ext_traefik_plugins_config-decode/`).
7. ServeHTTP sites stay dest exclude: after forced `b`, LAPI match → `passOrForcedCaptcha`; in `handleNextServeHTTP`, AppSec match → `next` with no buffer and no Query. Leave `recordProcessed` where it is. Alternative: skip only `LiveLookup` — rejected; stream/alone would still bounce from the store. Alternative: bypass before startup block — rejected; unpublished backends still 503.
8. Mock e2e `tests/e2e/mock/scenarios/request-bypass-rules/` (file-provider nested lists). Prove LAPI skip of a banned IP on a matching path, AppSec skip of mock `rpc2` on a matching path, and independence. Constructor failures stay unit tests. Alternative: real-stack Pester — rejected; mock is this repo's plugin-loader suite.

## Risks / Trade-offs

- [Public config break; leftover exclude YAML is silent] → README says the keys are gone; Traefik unused-key decode never reaches `New`. No alias.
- [Unanchored path `health` matches `/unhealthy`] → document; operators write `^/health$` for exact.
- [Method `POST` does not match `post`] → document; write `(?i)` or `^POST$` as needed. No silent case-fold.
- [Startup block still 503s bypassed health paths when a subscribed backend is unpublished] → keep explore order; operators who need those paths during startup set `bouncerStartupBlock: false`.
- [Compile twice at New] → one owner `httprule.New`; ValidateParams is the fail-closed gate; Bouncer still owns the stored `Set`.

## Migration Plan

**BREAKING.** Operators rewrite exclude strings as rule lists (`path: ^/healthz$`, not `example.com://health`). Rollback: restore the previous plugin version and the old keys. New binary ignores leftover exclude keys.

## Open Questions

None — explore rows stand. Propose clarified fully-empty vs `!` with an empty pattern on the compile-owner row.
