# Requirement
IssueKey: 2026-09-25-request-bypass-rules

Add per-leg request bypass rules so operators can skip the LAPI decision check, the AppSec hop, or both, for matching requests. Implement the matcher as its own package. It will later move to the upstream utilities library, so it must not import this plugin's other packages. Real end-to-end tests are required, not only unit tests.

This replaces the idea of BouncerAppsecExcludeRegex and BouncerLapiExcludeRegex. Those fields do not exist in this tree. Do not add them. Public config may break; there is no migration.

Two lists, same rule shape, same compiler:
- bouncerAppsecBypassRules — when a rule matches, skip the AppSec hop (no body buffer, no AppSec request). LAPI still runs unless its own list also matches.
- bouncerLapiBypassRules — when a rule matches, skip the LAPI decision lookup. AppSec still runs unless its own list also matches.

Authoring form (YAML middleware config, JSON field names camelCase as today):

```yaml
bouncerAppsecBypassRules:
  - method: GET                 # omit = any method
    path: ^/admin/              # omit = any path
    headers:                    # omit = ignore headers; several names = AND
      X-Health: ^ok$            # empty pattern = header is present
    cookies:                    # same, AND across names
      session: ^[a-f0-9]+$
  - path: ^/healthz$

bouncerLapiBypassRules:
  - path: ^/healthz$
```

Matching:
- One block is one exemption. Omitted field means any. Set fields must all match (AND). Rules in a list are OR. First match wins.
- method: case-insensitive HTTP method. Omit = any.
- path: Go RE2, unanchored MatchString against req.URL.Path (percent-decoded, not slash-normalized, not the query). The plugin does not insert ^ or $. `health` matches `/unhealthy`. Write `^/health$` for exact, `^/admin/` for a prefix.
- headers: name case-insensitive. Pattern is RE2 against each value of that header; one matching value is enough. Empty pattern means the header is present with any value. Several names are AND.
- cookies: same, against that cookie's value.
- A block with no path, no headers, and no cookies matches every request of that method (or every request if method is also omitted). Plugin construction must reject that fully empty rule.
- Invalid regexp fails plugin construction.
- WebSocket handshake GETs are inspected like any other GET. After an allow, Traefik tunnels frames; this plugin does not see them. Operators who need to skip a WebSocket path add a bypass rule.

Compilation (package of its own): New/compile rejects bad patterns and stores compiled rules (uppercased method or empty, compiled path regexp or nil, canonical header names with compiled patterns, cookie names with compiled patterns). Request check is a short loop: method, then path, then headers, then cookies. Go RE2 only. Parse the Cookie header once per request only when that rule list has a cookie predicate. Do not recompile per request.

Request-path placement: after trusted-IP skip and after the forced-decision ban header and startup-block 503. Bypass does not skip those. Trusted IPs already skip both legs. A LAPI bypass still runs AppSec. An AppSec bypass still runs LAPI.

Config names follow the Bouncer* request-policy prefix. JSON: bouncerAppsecBypassRules, bouncerLapiBypassRules.

Out of scope for the ask: moving the package to the utilities module in this change (own package here, move later); packed headerRegexp strings; a target: header:Name authoring form.

## Current (code)
- Public Config already has `BouncerAppsecExcludeRegex` / `json:"bouncerAppsecExcludeRegex"` and `BouncerLapiExcludeRegex` / `json:"bouncerLapiExcludeRegex"` (one RE2 string each, empty = off, comment: match `host://path`): `pkg/configuration/configuration.go`.
- `configuration.New` defaults both strings to `""`: `pkg/configuration/configuration.go`.
- `CompileExcludeRegex` trims, treats empty as off `(nil, nil)`, else `regexp.Compile`: `pkg/configuration/configuration.go`.
- `ValidateParams` compiles both and fails with the Go field name; invalid pattern fails `plugin.New` before LAPI Open: `pkg/configuration/configuration.go`, `plugin.go`, `zzz_plugin_test.go`.
- `bouncer.New` compiles again into `appsecExcludeRegex` / `lapiExcludeRegex` (`*regexp.Regexp`, nil = off) and returns the compile error: `pkg/bouncer/bouncer.go`.
- Match text is `host://path` (Host after `net.SplitHostPort` when that succeeds; `req.URL.Path` with one leading `/` stripped; empty or `/` → `host://`). Unanchored `MatchString`. Not `req.URL.Path` alone: `pkg/bouncer/bouncer.go` `excludeMatchString`, `excludedBy`.
- `ServeHTTP` order: disabled → next; startup-block 503 for unpublished subscribed legs; GetRemoteIP (ban on fail); trusted-IP skip (both legs); forced header `b` ban; then LAPI exclude → `passOrForcedCaptcha` (skips lookup, missing-LAPI failure, stream-unhealthy failure; AppSec may still run; forced `c` still applies): `pkg/bouncer/bouncer.go`.
- AppSec exclude is in `handleNextServeHTTP`: match → `next` with no body buffer and no AppSec Query; no match → `applyAppsecServeHTTP`: `pkg/bouncer/bouncer.go`.
- Trusted IPs skip LAPI and AppSec: `pkg/bouncer/bouncer.go`.
- Unit tests for compile, `host://path`, LAPI skip, AppSec skip, forced `b`/`c`, independence: `pkg/bouncer/zzz_exclude_regex_test.go`, `pkg/configuration/zzz_configuration_test.go`.
- Live spec freezes the two strings, `host://path`, and that placement: `openspec/specs/core_plugin_middleware_bouncer/spec.md`. Validation SHALL: `openspec/specs/core_plugin_middleware_config-validation/spec.md`.
- README documents both knobs: `README.md`. Usage: `knowledge/devdocs/core_plugin_middleware.md`, `knowledge/devdocs/core_plugin_middleware_config-validation.md`.
- The strings landed this same day: `openspec/changes/archive/2026-09-25-bouncer-exclude-regex/`.
- `bouncerAppsecBypassRules` / `bouncerLapiBypassRules` and a method/path/headers/cookies matcher package: not found.
- Real e2e covering exclude regex or bypass rules: not found (`tests/e2e/real/`, `tests/e2e/mock/`).

## Desired
- Two public lists, same rule shape, same compiler: `bouncerAppsecBypassRules` skips the AppSec hop (no body buffer, no AppSec request); `bouncerLapiBypassRules` skips the LAPI decision lookup. Legs are independent.
- Matcher is its own package. It must not import this plugin's other packages (later move to the utilities library is out of this change).
- Authoring: optional method, path, headers map, cookies map. Omit = any. Set fields AND. List OR. First match wins.
- Path: Go RE2, unanchored `MatchString` on `req.URL.Path` (percent-decoded, not slash-normalized, not the query). Plugin does not insert `^` or `$`.
- Headers: name case-insensitive; RE2 against each value (one hit enough); empty pattern = header present. Cookies: same against that cookie's value.
- Fully empty rule (no path, no headers, no cookies — method-only or nothing) fails plugin construction. Invalid regexp fails construction.
- Compile once: uppercased method or empty, compiled path regexp or nil, canonical header names, cookie names. Request loop: method, path, headers, cookies. Parse Cookie once per request only when that list has a cookie predicate. Do not recompile per request.
- Placement: after trusted-IP skip, forced-decision ban header, and startup-block 503. Bypass does not skip those.
- WebSocket handshake GET is a normal GET; frames after allow are not seen.
- JSON camelCase as today. `Bouncer*` request-policy prefix.
- Do not add `BouncerAppsecExcludeRegex` / `BouncerLapiExcludeRegex`. Public config may break; no migration.
- Real end-to-end tests, not only unit tests.

## Affected
- `pkg/configuration/configuration.go` — public fields, defaults, `ValidateParams`
- `pkg/bouncer/bouncer.go` — compile at `New`, `ServeHTTP` / `handleNextServeHTTP` skip
- new matcher package under `pkg/` (name not in the ask)
- `plugin.go` — construction failure still returns nil handler
- `openspec/specs/core_plugin_middleware_bouncer/spec.md` and `openspec/specs/core_plugin_middleware_config-validation/spec.md`
- `README.md`, `knowledge/devdocs/core_plugin_middleware.md`, `knowledge/devdocs/core_plugin_middleware_config-validation.md`
- `pkg/bouncer/zzz_exclude_regex_test.go` and configuration/plugin tests that name the exclude strings
- `tests/e2e/` — no coverage today

## Out of scope
- Moving the matcher package into the utilities module in this change.
- Packed `headerRegexp` strings.
- A `target: header:Name` authoring form.
- Changing trusted-IP skip, forced-decision header, or startup-block 503.
- A captcha-leg bypass list.
- Aliases or migration from `bouncerAppsecExcludeRegex` / `bouncerLapiExcludeRegex`.

## Unknowns
- Matcher package path/name under `pkg/` (ask: own package, no plugin imports).
- Whether dest's exclude-regex strings, `CompileExcludeRegex`, `excludeMatchString`, live SHALL rows, README, and unit tests are deleted in this change (ask: fields “do not exist” / “do not add”; dest has them).
- Whether a LAPI bypass also skips missing-subscribed-LAPI failure action and stream/alone unhealthy failure (dest LAPI exclude does; ask names “decision lookup”).
- Which e2e suite is “real”: `tests/e2e/real/` (Docker CrowdSec) vs `tests/e2e/mock/` (Traefik binary + mock LAPI). Dest exclude has neither.
- Cookie-name case: headers are case-insensitive; cookies “same” vs RFC cookie names.
- What “canonical header names” means at compile (`textproto.CanonicalMIMEHeaderKey` vs lower).
- Whether fully-empty-rule rejection is `ValidateParams`, matcher New, or `bouncer.New`.
- Whether bypass still increments LAPI `processed` (dest counts before exclude).
- Operator blast of dropping `host://path` (port-stripped Host) for path-only RE2.

## Tensions
- Ask: “Those fields do not exist in this tree. Do not add them.” Dest `master` has `BouncerAppsecExcludeRegex` and `BouncerLapiExcludeRegex` on Config, compiled in `bouncer.New`, used on ServeHTTP, documented, specced, and unit-tested (`pkg/configuration/configuration.go`, `pkg/bouncer/bouncer.go`, `openspec/specs/core_plugin_middleware_bouncer/spec.md`). Same ask: “This replaces the idea of” those fields, and “Public config may break; there is no migration.”
- Ask matches path on `req.URL.Path`. Dest exclude matches `host://path` with the leading slash stripped (`pkg/bouncer/bouncer.go` `excludeMatchString`). `health` on dest does not mean `/unhealthy` unless that substring appears in `host://path`.
- Live SHALL rows require the two exclude strings (`openspec/specs/core_plugin_middleware_bouncer/spec.md`, `openspec/specs/core_plugin_middleware_config-validation/spec.md`). This ask replaces that freeze.
- Ask: skip “LAPI decision lookup.” Dest LAPI exclude also skips missing-LAPI failure action and stream-unhealthy failure (`pkg/bouncer/bouncer.go`).
