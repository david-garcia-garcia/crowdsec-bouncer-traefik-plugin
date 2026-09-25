## 1. Matcher package

- [ ] 1.1 Add `pkg/httprule` with authoring `Rule` (`method`, `path`, `headers`, `cookies` json tags) and `New([]Rule) (*Set, error)`. Stdlib only. No imports of this plugin's other packages
- [ ] 1.2 Compile: trim method; optional single leading `!` stripped before `regexp.Compile`; reject `!!` and `!` with an empty pattern; compile path/header/cookie patterns as Go RE2; header names via `CanonicalMIMEHeaderKey`; cookie names as written. Empty path/method after trim = any. Reject a rule when path, headers, and cookies are absent AND method is any (omitted, empty, or `.*`). A method-only rule passes
- [ ] 1.3 `Set.Match(*http.Request)`: OR across rules, first match wins; AND method → path → headers → cookies. Unanchored `MatchString` on `req.Method` and `req.URL.Path`. Header values from `req.Header[canonical]` (one hit enough; empty pattern = present). Cookie names case-sensitive. Parse Cookie once per `Match` only when that `Set` has a cookie predicate. Do not insert `^`/`$`, do not lowercase, do not force `(?i)`
- [ ] 1.4 Tests in `pkg/httprule`: empty list matches nothing; method-only; `!POST`; `!!` and `!` fail New; `{}` and `{method: ".*"}` fail New; invalid RE2 fails New; unanchored path `health` vs `/unhealthy`; header AND / empty-present; cookie case; first-match wins

## 2. Configuration

- [ ] 2.1 Replace `BouncerAppsecExcludeRegex` / `BouncerLapiExcludeRegex` with `BouncerAppsecBypassRules` / `BouncerLapiBypassRules` (`[]httprule.Rule`), json tags alphabetical (AppSec bypass before `BouncerAppsecFailureAction`; LAPI bypass before `BouncerLapiFailureAction`). Defaults empty in `configuration.New`. Delete `CompileExcludeRegex`
- [ ] 2.2 `ValidateParams` calls `httprule.New` for each list, wraps errors with the Go field name, discards the set. Empty lists pass. Fully empty / invalid rules fail
- [ ] 2.3 Rewrite `pkg/configuration/zzz_configuration_test.go` exclude cases onto the lists (empty pass; `{}` and `.*` method fail; method-only pass; `(` path/method fail and name the field)

## 3. Bouncer request path

- [ ] 3.1 `bouncer.New` compiles both lists into `*httprule.Set`, returns the compile error. Delete `appsecExcludeRegex` / `lapiExcludeRegex`, `excludeMatchString`, `excludedBy`. Do not compile on the request path
- [ ] 3.2 After forced `b`, if the LAPI set matches, go to `passOrForcedCaptcha`. In `handleNextServeHTTP`, if the AppSec set matches, call `next` and skip `applyAppsecServeHTTP`. Leave `recordProcessed` where it is
- [ ] 3.3 Rewrite `pkg/bouncer/zzz_exclude_regex_test.go` onto bypass lists (LAPI skip of store/unhealthy; AppSec skip of Query; independence; forced `b`/`c`; trusted IP; unanchored path; Host not in path)
- [ ] 3.4 Rewrite `zzz_plugin_test.go` `TestNew_RejectsInvalidExcludeRegex` onto invalid bypass rules (nil handler, no LAPI Open)
- [ ] 3.5 Confirm `pkg/lapi/identity.go` / `pkg/appsec/session.go` do not hash the lists (no code change unless a test proves they would)

## 4. Mock e2e

- [ ] 4.1 Add `tests/e2e/mock/scenarios/request-bypass-rules/{dynamic.yml,run.sh}` with nested rule lists. Prove a banned IP still reaches origin on a LAPI-matching path, AppSec mock `rpc2` is skipped on an AppSec-matching path, and a LAPI match does not skip AppSec (and the reverse)

## 5. Docs

- [ ] 5.1 README: replace the two exclude knobs with the two lists (omit = any; AND/OR; unanchored path on `req.URL.Path`; method RE2 plus optional `!`; empty header/cookie pattern = present; fully empty rule fails `New`; leftover exclude keys are ignored). Place next to the related failure-action entries
- [ ] 5.2 Usage `knowledge/devdocs/core_plugin_middleware.md`: drop Language **Exclude match string**; document bypass after trusted-IP and forced `b`; path owner `req.URL.Path`; knobs stay off reclaim keys. `core_plugin_middleware_config-validation.md`: `httprule.New` from `ValidateParams`. `core_plugin_middleware_forced-decision.md`: retarget LAPI exclude to LAPI bypass

## 6. Verify

- [ ] 6.1 `go test ./pkg/httprule/ ./pkg/configuration/ ./pkg/bouncer/ ./pkg/lapi/ ./pkg/appsec/` and `go test .` plus `golangci-lint run ./pkg/httprule/... ./pkg/configuration/... ./pkg/bouncer/...`
- [ ] 6.2 `make e2e_mock` (or the harness for `request-bypass-rules`) so the new scenario passes
