# Explore
IssueKey: 2026-09-25-request-bypass-rules

Human correction this run: the new lists **replace and remove** `BouncerAppsecExcludeRegex` / `BouncerLapiExcludeRegex`. No alias, no migration shim. `requirement.md` Current is dest-true; the Desired line “those fields do not exist / do not add them” is the inverted prepare wording and is not the ask.

## Concepts

**Bypass rule**:
One exemption block (optional method, path, headers map, cookies map). Omitted field = any. Set fields AND. List OR, first match wins. Not a trusted-IP skip, not the forced-decision header, not a captcha-leg list.

**Exclude match string** (dest, removed by this change):
`host://path` from `excludeMatchString` (`pkg/bouncer/bouncer.go`). Host is `req.Host` after `net.SplitHostPort` when that succeeds; path is `req.URL.Path` with one leading `/` stripped. This change does not keep that owner.

**Matcher package** (`pkg/httprule`):
Compile-once HTTP request rules. Must not import this plugin’s other packages (later utilities move is out of this change). Config holds the authoring `[]httprule.Rule`; Bouncer holds the compiled set.

Units this change would touch:

| Unit | Path | Job |
| --- | --- | --- |
| Public Config | `pkg/configuration/configuration.go` | Replace the two strings with `BouncerAppsecBypassRules` / `BouncerLapiBypassRules`; defaults; `ValidateParams` |
| Exclude compiler | `CompileExcludeRegex` same file | Delete with the strings |
| Bouncer request path | `pkg/bouncer/bouncer.go` | Drop `appsecExcludeRegex` / `lapiExcludeRegex`, `excludeMatchString`, `excludedBy`; compile matcher at `New`; same skip sites |
| Matcher | new `pkg/httprule` | New/compile + `Match(*http.Request)`; no plugin imports |
| Plugin New | `plugin.go` | Still `nil, err` before LAPI Open when validation fails |
| Live catalog | `openspec/specs/core_plugin_middleware_bouncer/spec.md`, `openspec/specs/core_plugin_middleware_config-validation/spec.md` | Replace exclude SHALL |
| Usage | `knowledge/devdocs/core_plugin_middleware.md`, `core_plugin_middleware_config-validation.md`, `core_plugin_middleware_forced-decision.md` | Retarget exclude language to bypass |
| Operator README | `README.md` | Replace the two knobs |
| Unit tests | `pkg/bouncer/zzz_exclude_regex_test.go`, `pkg/configuration/zzz_configuration_test.go`, `zzz_plugin_test.go` | Rewrite onto lists + path/header/cookie match |
| Mock e2e | new `tests/e2e/mock/scenarios/` folder | Traefik decode + skip through mock LAPI/AppSec |

```
ServeHTTP
  disabled → next
  startup-block 503 (unpublished subscribed legs)
  GetRemoteIP → recordProcessed; ban on fail
  trusted-IP → next (skips LAPI and AppSec)
  forced header b → ban (no lookup)
  LAPI bypass Match? → passOrForcedCaptcha
       (skips Lookup/LiveLookup, missing-LAPI failure, stream-unhealthy failure;
        forced c still applies; AppSec may still run)
  else today's LAPI path
  pass → handleNextServeHTTP
       AppSec bypass Match? → next (no body buffer, no AppSec Query)
       else applyAppsecServeHTTP
```

Bypass does not skip trusted-IP, forced `b`, or startup-block 503.

### Reproduce

Not a failing request. **Confirmed dest exclude** (`go test ./pkg/bouncer/ ./pkg/configuration/ -count=1 -timeout 60s -run "Exclude|exclude"`: ok). Dest matches `host://path`, LAPI skip continues at `passOrForcedCaptcha` (store hit and stream-unhealthy do not apply: `TestServeHTTP_lapiExcludeSkipsStreamStoreAndUnhealthy`), AppSec skip is `handleNextServeHTTP` → `next` with no Query. `bouncerAppsecBypassRules` / `pkg/httprule`: not found.

### Call sites of the old strings (bounded)

Roots searched (worktree, not vendor, not `devstate/`, not `openspec/changes/archive/`): `BouncerAppsecExcludeRegex|BouncerLapiExcludeRegex|bouncerAppsecExcludeRegex|bouncerLapiExcludeRegex|CompileExcludeRegex|excludeMatchString|excludedBy|appsecExcludeRegex|lapiExcludeRegex`.

**11 files, all migratable in this change.** `tests/e2e/**` and `examples/**`: **0**. Archive `openspec/changes/archive/2026-09-25-bouncer-exclude-regex/` is historical; do not migrate.

| File | Occurrences | Role |
| --- | --- | --- |
| `pkg/configuration/configuration.go` | 10 | Fields, `New` defaults `""`, `CompileExcludeRegex`, `ValidateParams` |
| `pkg/bouncer/bouncer.go` | 13 | Two `*regexp.Regexp` fields; compile at `New`; `excludeMatchString`; `excludedBy` **2 production calls** (`ServeHTTP` LAPI, `handleNextServeHTTP` AppSec) |
| `pkg/bouncer/zzz_exclude_regex_test.go` | 24 | 16 tests (compile, `host://path`, LAPI/AppSec skip, forced `b`/`c`, trusted IP, port, query) |
| `pkg/configuration/zzz_configuration_test.go` | 13 | `ValidateParams` invalid/whitespace + `TestCompileExcludeRegex` |
| `zzz_plugin_test.go` | 6 | `TestNew_RejectsInvalidExcludeRegex` |
| `README.md` | 3 | Two operator knobs |
| `openspec/specs/core_plugin_middleware_bouncer/spec.md` | 14 | Host+path exclude SHALL + scenarios |
| `openspec/specs/core_plugin_middleware_config-validation/spec.md` | 9 | Invalid exclude regex SHALL + coverage bullet |
| `knowledge/devdocs/core_plugin_middleware.md` | 2 | Language **Exclude match string** + How to use |
| `knowledge/devdocs/core_plugin_middleware_config-validation.md` | 6 | Trim/compile How to use + snippet |
| `knowledge/devdocs/core_plugin_middleware_forced-decision.md` | 2 | Header `c` vs LAPI exclude |

Not in LAPI ownership / SessionHex (`pkg/lapi/identity.go` has no exclude fields). Usage `core_plugin_lapi_reclaim-key.md` already keeps exclude off the keys.

### Outside facts

- Traefik Yaegi mapstructure: unused keys dropped (`knowledge/research/ext_traefik_plugins_config-decode/`). After the fields are gone, leftover `bouncerAppsecExcludeRegex` YAML does not fail construct and never reaches `New`.
- Nested YAML maps already decode (`bouncerDecisionScopeHeaders`, `bouncerOriginBasedDecisionRemap`). No in-tree `[]struct` on Config yet; WeaklyTypedInput is the same decoder.
- Header names: `textproto.CanonicalMIMEHeaderKey` (Go `net/http` Header keys). Cookie names: case-sensitive (`net/http` `Request.Cookie` / RFC 6265), not header-canonical.
- Subpackages are Yaegi-loadable (`knowledge/research/ext_traefik_plugins_yaegi-constructor/`). Matcher as `pkg/httprule` is fine; `CreateConfig`/`New` stay at module root.

E2e in this repo: **mock** = `tests/e2e/mock/` (Traefik binary + mock LAPI, `make e2e_mock`, layout `scenarios/<name>/{dynamic.yml,run.sh}`). **Real-stack** = `tests/e2e/real/` (Docker Traefik + live CrowdSec Pester). Dest exclude has neither.

## Decisions

- Chosen: delete `BouncerAppsecExcludeRegex` / `BouncerLapiExcludeRegex`, `CompileExcludeRegex`, `excludeMatchString`, `excludedBy`. Public config may break; Traefik will silently drop leftover keys. No alias, no `host://path` converter.
- Chosen seam: same ServeHTTP sites as dest exclude (`bouncer.go` after forced `b`; `handleNextServeHTTP` before AppSec). LAPI match → `passOrForcedCaptcha`. AppSec match → `next` with no buffer and no Query.
- Chosen matcher path: `pkg/httprule` (HTTP request rules, not a CrowdSec noun). `configuration` and `bouncer` import it; it imports only stdlib.
- Chosen compile owner: `httprule.New([]Rule) (*Set, error)` rejects invalid RE2 and fully empty rules (no path, no headers, no cookies — method-only or nothing). `ValidateParams` calls it so `plugin.New` fails before LAPI Open (error text names the Go field). `bouncer.New` compiles again to store `*httprule.Set` (same split as dest `CompileExcludeRegex`).
- Chosen path text: unanchored `MatchString` on `req.URL.Path` as written. Plugin does not insert `^`/`$`. Percent-decoded, not slash-normalized, not the query. Do not use `excludeMatchString`.
- Chosen headers: compile with `CanonicalMIMEHeaderKey`; AND across names; empty pattern = header present (any value); RE2 against each value, one hit enough.
- Chosen cookies: same predicate shape; names case-sensitive; parse the Cookie header once per request only when that compiled list has a cookie predicate.
- Chosen e2e: new mock scenario under `tests/e2e/mock/scenarios/` (file-provider `dynamic.yml` nested lists). Prove LAPI skip of a banned IP on a matching path, AppSec skip of mock `rpc2` on a matching path, and independence. Constructor failures stay unit tests. Do not require Pester/Docker CrowdSec for this ask.
- Chosen live contract: fold `core_plugin_middleware_bouncer` (lists + request path) and `core_plugin_middleware_config-validation` (compile/empty/invalid). Retarget forced-decision usage that names LAPI exclude. No new spec family. Do not migrate archive.
- Rejected: keep old strings beside the lists (human correction; Out of scope aliases).
- Rejected: `pkg/bypassrule` as the package name (ties a later utilities move to this plugin’s knob).
- Rejected: moving the package to traefik-middleware-utilities in this change (Out of scope).
- Rejected: packed `headerRegexp` strings and `target: header:Name` (Out of scope).
- Rejected: a captcha-leg list; changing trusted-IP, forced `b`, or startup-block 503.
- Rejected: real-stack Pester as the required “real” e2e (ask contrasts unit tests; mock is this repo’s plugin-loader suite and already decodes nested YAML).
- Live contract: `openspec/specs/core_plugin_middleware_bouncer`, `openspec/specs/core_plugin_middleware_config-validation`. Forced-decision spec scenarios that only name exclude as a lookup skip retarget to LAPI bypass.

## Open questions

- Q: Where does the matcher package live under pkg/?
  Rank: additive asked — new package this change creates; criterion Implement the matcher as its own package
  Decision: assumed — pkg/httprule. Authoring type Rule with json method, path, headers, cookies. Compiled Set. No imports of this plugin.
  By: explore

- Q: Does a LAPI bypass also skip missing-subscribed-LAPI failure and stream/alone unhealthy failure?
  Rank: bounded asked — same ServeHTTP site as dest LAPI exclude (bouncer.go excludedBy then passOrForcedCaptcha, 1 production call); Desired skip the LAPI decision lookup
  Decision: assumed — yes, by keeping that site. Do not look up and then ignore. Forced c still applies on the pass path.
  By: explore

- Q: Which e2e suite is real (tests/e2e/real/ vs tests/e2e/mock/)?
  Rank: additive asked — new scenario this change creates; Desired Real end-to-end tests, not only unit tests
  Decision: assumed — mock tests/e2e/mock/scenarios/. That is this repo's Traefik-plugin e2e. Nested rule lists go in dynamic.yml. Pester/Docker CrowdSec is not required.
  By: explore

- Q: Are cookie names case-insensitive like headers, or RFC cookie-name case-sensitive?
  Rank: additive asked — new cookie predicate this change creates; Unknowns on requirement.md
  Decision: assumed — case-sensitive names (net/http cookie parse). Headers stay case-insensitive via CanonicalMIMEHeaderKey. Same means AND / empty = present / RE2 on value, not header canonicalization on cookie names.
  By: explore

- Q: What canonical header names means at compile?
  Rank: additive asked — new compile step this change creates; Desired canonical header names with compiled patterns
  Decision: assumed — textproto.CanonicalMIMEHeaderKey. Request check uses req.Header[canonical] values (every value, not Header.Get).
  By: explore

- Q: Where is fully-empty-rule rejection owned (ValidateParams, matcher New, or bouncer.New)?
  Rank: additive asked — new constructor reject this change creates; Desired Plugin construction must reject that fully empty rule
  Decision: assumed — httprule.New is the owner. ValidateParams calls it (fail plugin.New before LAPI Open, error names BouncerAppsecBypassRules / BouncerLapiBypassRules). bouncer.New calls it again to store the set.
  By: explore

- Q: Does bypass still increment LAPI processed (dest counts before exclude)?
  Rank: bounded asked — existing recordProcessed at ServeHTTP before trusted skip (bouncer.go); Unknowns on requirement.md
  Decision: assumed — yes. Leave recordProcessed where it is. Bypass is still a handled request, like dest exclude.
  By: explore

- Q: What is the operator blast of dropping host://path for path-only RE2?
  Rank: bounded asked — dest match-string owner with enumerated tests/docs (same 11 files); Desired path on req.URL.Path; human correction public may break
  Decision: assumed — accept the break. Document path-only unanchored RE2. health matches /unhealthy. example.com://health will not match path /health. No converter.
  By: explore

- Q: Do we delete dest's exclude-regex strings, CompileExcludeRegex, excludeMatchString, live SHALL rows, README, and unit tests in this change?
  Rank: bounded asked — existing public Config contract with 11 enumerated files (roots above); Desired Public config may break, no migration; Out of scope Aliases or migration; human correction REPLACE AND REMOVE
  Decision: resolved — yes. Remove both fields and every in-tree caller listed above. No shim. Leftover operator YAML is dropped by Traefik unused-key decode.
  By: explore

- Q: Who already owns client address, path, and Host for matching?
  Rank: additive asked — new match reads request identity fields; commandments One job, one owner
  Decision: resolved — client address stays ip.GetRemoteIP / clientRequest (bypass does not parse XFF). Path owner is req.URL.Path as net/http already decoded it; do not rebuild from RequestURI, EscapedPath, or AppSec forwarded URI. Host is not part of the path match; a Host header rule reads req.Header (canonical). Do not reconstruct Host with SplitHostPort (that was dest exclude).
  By: explore
