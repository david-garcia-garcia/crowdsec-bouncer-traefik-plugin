## 1. Configuration

- [x] 1.1 Add `BouncerAppsecExcludeRegex` and `BouncerLapiExcludeRegex` strings on `Config`, json tags `bouncerAppsecExcludeRegex` / `bouncerLapiExcludeRegex`, alphabetical by json tag (AppSec exclude before `BouncerAppsecFailureAction`; LAPI exclude before `BouncerLapiFailureAction`). Default empty in `configuration.New`
- [x] 1.2 Add `CompileExcludeRegex(s string) (*regexp.Regexp, error)`: trim; empty → `(nil, nil)`; else `regexp.Compile`. Use it from `ValidateParams` (return the error, discard the value). Do not put `*regexp.Regexp` on `Config`
- [x] 1.3 Tests in `pkg/configuration/zzz_configuration_test.go`: empty and whitespace-only pass; `(` on each field fails and names the Go field; valid patterns pass

## 2. Bouncer compile and match

- [x] 2.1 `bouncer.New` calls `CompileExcludeRegex` for both knobs, stores `appsecExcludeRegex` and `lapiExcludeRegex` (`*regexp.Regexp`; nil = off), returns the compile error. Do not compile on the request path
- [x] 2.2 Add `excludeMatchString(httpReq *http.Request) string` in `pkg/bouncer`: Host is `req.Host`; use `net.SplitHostPort` when it succeeds; path is `req.URL.Path`; empty or nil URL Path → `/`; concatenate. Do not call `captcha.RequestDomain`. Do not use AppSec forwarded Host/URI, `URL.String()`, `RequestURI`, or `EscapedPath`
- [x] 2.3 Tests for match string: `example.com:443` + `/health` → `example.com/health`; query ignored; empty Path → `host/`; IPv6 with port loses brackets; bare `[::1]` stays as Host wrote it

## 3. ServeHTTP skip

- [x] 3.1 After forced `b`, if `lapiExcludeRegex` matches `excludeMatchString`, go to `passOrForcedCaptcha` (skip missing-LAPI failure action, `LookupRemediation`, `LiveLookup`, stream-unhealthy failure). In `handleNextServeHTTP`, if `appsecExcludeRegex` matches, call `next` and skip `applyAppsecServeHTTP`
- [x] 3.2 Tests in `pkg/bouncer` (`zzz_forced_decision_test.go` neighbors or a new `zzz_exclude_regex_test.go`): empty exclude still looks up; LAPI exclude skips stream store and live/none lookup; AppSec exclude skips Query; LAPI exclude does not skip AppSec; forced `b` still bans; forced `c` still captchas after LAPI exclude; trusted IP still skips the whole plugin
- [x] 3.3 `plugin.New` with invalid exclude regex returns a nil handler and that error without opening LAPI (same family as `TestNew_RejectsEmptyCaptchaKeys`)
- [x] 3.4 Confirm `pkg/lapi/identity.go` / `pkg/appsec/session.go` do not hash the new strings (no code change unless a test proves they would)

## 4. Docs

- [x] 4.1 README: document both knobs (empty = off; `{host}/path`; unanchored RE2; `^...$` to anchor; port and query stripped; invalid pattern fails `New`). Place next to the related `BouncerAppsecFailureAction` / `BouncerLapiFailureAction` entries
- [x] 4.2 Usage `knowledge/devdocs/core_plugin_middleware.md`: request-policy exclude sits after trusted-IP and forced `b`; match reuses `req.Host` / `req.URL.Path`; knobs stay off reclaim keys. `knowledge/devdocs/core_plugin_middleware_config-validation.md`: invalid RE2 fails `ValidateParams`

## 5. Verify

- [x] 5.1 `go test ./pkg/configuration/ ./pkg/bouncer/ ./pkg/lapi/ ./pkg/appsec/` and `go test .` plus `golangci-lint run ./pkg/configuration/... ./pkg/bouncer/...`
