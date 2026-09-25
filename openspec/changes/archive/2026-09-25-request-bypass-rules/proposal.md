## Why

Dest today can skip one CrowdSec leg only with a single unanchored RE2 on a reconstructed `host://path` (`bouncerAppsecExcludeRegex` / `bouncerLapiExcludeRegex`). Operators need per-leg exemptions that match method, path, headers, and cookies independently, without that host+path string. The two strings landed the same day; this change replaces them before they freeze as the public surface.

## What Changes

- **BREAKING.** Delete `BouncerAppsecExcludeRegex` / `BouncerLapiExcludeRegex`, `CompileExcludeRegex`, `excludeMatchString`, and `excludedBy`. No alias, no `host://path` converter. Traefik silently drops leftover YAML keys.
- Two public lists, same rule shape, same compiler: `bouncerAppsecBypassRules` skips the AppSec hop (no body buffer, no AppSec Query); `bouncerLapiBypassRules` skips LAPI decision lookup, missing-subscribed-LAPI failure, and stream/alone unhealthy failure, then continues at `passOrForcedCaptcha`. Legs stay independent.
- Matcher lives in new `pkg/httprule` (stdlib only; later utilities move is out of this change). Config holds `[]httprule.Rule`; Bouncer stores `*httprule.Set`.
- Authoring: optional `method`, `path`, `host`, `headers`, `cookies`. Omit = any. Set fields AND. List OR, first match wins. Method is Go RE2 against `req.Method` (optional leading `!` negates). Path is unanchored RE2 on `req.URL.Path`. Host is unanchored RE2 on the hostname of `req.Host` (port stripped).
- Placement stays the dest exclude sites: after trusted-IP skip, forced `b`, and startup-block 503. Bypass does not skip those. Forced `c` still applies after a LAPI match. `recordProcessed` stays where it is.
- Fully empty rules (every predicate is any) and invalid RE2 fail `ValidateParams` / `plugin.New` before LAPI Open. A method-only rule is valid.
- Mock e2e under `tests/e2e/mock/scenarios/` proves Traefik decode plus LAPI skip, AppSec skip, and independence. Constructor failures stay unit tests.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_bouncer`: per-leg bypass lists replace host+path exclude strings; match is method/path/host/headers/cookies on the request; same ServeHTTP skip sites.
- `core_plugin_middleware_config-validation`: `httprule.New` is the compile/empty/invalid gate; error text names `BouncerAppsecBypassRules` / `BouncerLapiBypassRules`.

## Impact

- `pkg/httprule` (new; no plugin imports)
- `pkg/configuration/configuration.go` (lists alphabetical by json tag; `ValidateParams`; delete exclude strings and `CompileExcludeRegex`)
- `pkg/bouncer/bouncer.go` (compile at `New`; drop exclude fields and match helpers; same skip sites)
- `plugin.go` (still `nil, err` before LAPI Open)
- Tests: `pkg/httprule`, `pkg/bouncer/zzz_exclude_regex_test.go` rewrite, configuration and plugin constructor tests
- Mock e2e: `tests/e2e/mock/scenarios/request-bypass-rules/`
- README, usage `core_plugin_middleware.md`, `core_plugin_middleware_config-validation.md`, `core_plugin_middleware_forced-decision.md`
- Do not change trusted-IP skip, forced `b`, startup-block 503, captcha-leg lists, `pkg/lapi/identity.go`, or `pkg/appsec/session.go`
- Do not migrate `openspec/changes/archive/2026-09-25-bouncer-exclude-regex/`
