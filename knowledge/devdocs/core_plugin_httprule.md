# HTTP request rules

## Language

**Rule**:
One authoring exemption in `pkg/httprule`: optional method, path, host, headers map, and cookies map. An omitted field means any. Set fields AND. Not a trusted-IP skip, not an action-rule token, not a captcha-leg list.
_Avoid_: exclude regex, `host://path`, packed `headerRegexp`, `target: header:Name`

**Set**:
The compiled list `httprule.New` returns. An empty list matches nothing. `Match` is OR across rules; the first matching rule wins. `Matching` returns every matching index in list order. A nil Set matches nothing.
_Avoid_: compiling on the request path, putting compiled regexes on Config

**ActionRule**:
One authoring row beside `Rule`: unique `name`, `action` tokens, and embedded predicates. Traefik YAML stays flat via squash/inline. Not a field on `Rule`.
_Avoid_: first-match-wins fold, putting `name` / `action` on `Rule`

**ActionSet**:
The compiled list `httprule.NewActionSet` returns. Predicate match stays on `Set`; names and tokens sit beside it. `Matching` returns every hit; callers zip Ban / Captcha / SkipLapi / SkipAppsec.
_Avoid_: interpreting action tokens inside `Set.Match`

## Overview

Compile request exemptions once with `httprule.New`. Config holds `[]ActionRule`; Bouncer stores `*ActionSet`. Predicate compile stays `httprule.New`. The package imports only the Go standard library. ServeHTTP fold stays on `core_plugin_middleware_action-rules.md`. Constructor reject wrapping stays on `core_plugin_middleware_config-validation.md`.

## How to use

- Call `httprule.New` once at construct for predicate-only lists. Call `httprule.NewActionSet` for `bouncerActionRules`. Do not compile on the request path. Store `*Set` or `*ActionSet`. Call `Set.Match(*http.Request)` for first-wins boolean; call `Matching(*http.Request)` when every hit must contribute.
- Do not import this plugin's other packages from `pkg/httprule`.
- Method: unanchored Go RE2 `MatchString` on `req.Method`. Do not insert `^` or `$`. Do not lowercase. Do not force `(?i)`. Omit or empty after trim is any. Optional single leading `!` (outside the pattern) negates (`!POST`, `!^POST$`). `!!` and `!` with an empty pattern fail `New`.
- Path: unanchored `MatchString` on `req.URL.Path` as `net/http` decoded it. Do not rebuild from `RequestURI`, `EscapedPath`, or AppSec forwarded URI. Host is not in the path. Query is not in the path.
- Host: unanchored `MatchString` on the hostname of `req.Host`. When `net.SplitHostPort` succeeds, match that host (`example.com:443` → `example.com`, `[::1]:443` → `::1`). When it fails, match `req.Host` unchanged. Do not read the Host header map. Do not include scheme, port, or path. Omit or empty after trim is any. No leading `!`. A host-only rule is valid.
- Headers: compile names with `textproto.CanonicalMIMEHeaderKey`. AND across names. Empty pattern means the header is present. Otherwise RE2 against each value; one hit is enough. Use `req.Header[canonical]`, not `Header.Get`.
- Cookies: same predicate shape; names are case-sensitive. Parse the Cookie header once per request only when this Set has a cookie predicate.
- Reject a fully empty rule (path, host, headers, and cookies absent AND method any — omitted, empty after trim, or `.*`). A method-only or host-only rule is valid.
- Invalid RE2 on method, path, host, header, or cookie fails `New`. The host error names `host`.

## Pattern snippet

```go
set, err := httprule.NewActionSet([]httprule.ActionRule{{Name: "healthz", Action: []string{httprule.ActionBypass}, Rule: httprule.Rule{Path: "^/healthz$"}}})
if err != nil {
	return nil, err
}
hits := set.Matching(httpReq)
```

## Key files

- `pkg/httprule/rule.go`
- `pkg/httprule/set.go`
- `pkg/httprule/action.go`
- `pkg/configuration/configuration.go` (`BouncerActionRules`)
- `pkg/bouncer/bouncer.go` (`actionRules`)

## Gotchas

- Unanchored `health` matches `/unhealthy`. Operators who want an exact path write `^/health$`.
- Host match text is the hostname only. `example.com:443` matches `^example.com$`. `[::1]:443` matches `^::1$`, not `^\[::1\]$`.
- Method `^post$` does not match `POST`. Write `(?i)` or `^POST$`.
- `example.com://health` does not match path `/health`.
- Empty lists pass `New` and match nothing. A list with one fully empty rule fails.
- `ValidateParams` calls `NewActionSet` and discards the set; `bouncer.New` compiles again to store it (`core_plugin_middleware_config-validation.md`).
