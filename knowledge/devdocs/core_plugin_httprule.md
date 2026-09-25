# HTTP request rules

## Language

**Rule**:
One authoring exemption in `pkg/httprule`: optional method, path, headers map, and cookies map. An omitted field means any. Set fields AND. Not a trusted-IP skip, not the forced-decision header, not a captcha-leg list.
_Avoid_: exclude regex, `host://path`, packed `headerRegexp`, `target: header:Name`

**Set**:
The compiled list `httprule.New` returns. An empty list matches nothing. Match is OR across rules; the first matching rule wins. A nil Set matches nothing.
_Avoid_: compiling on the request path, putting compiled regexes on Config

## Overview

Compile request exemptions once with `httprule.New`. Config holds `[]Rule`; Bouncer stores `*Set`. The package imports only the Go standard library. ServeHTTP skip sites stay on `core_plugin_middleware.md`. Constructor reject wrapping stays on `core_plugin_middleware_config-validation.md`.

## How to use

- Call `httprule.New` once at construct. Do not compile on the request path. Store `*Set`. Call `Set.Match(*http.Request)`.
- Do not import this plugin's other packages from `pkg/httprule`.
- Method: unanchored Go RE2 `MatchString` on `req.Method`. Do not insert `^` or `$`. Do not lowercase. Do not force `(?i)`. Omit or empty after trim is any. Optional single leading `!` (outside the pattern) negates (`!POST`, `!^POST$`). `!!` and `!` with an empty pattern fail `New`.
- Path: unanchored `MatchString` on `req.URL.Path` as `net/http` decoded it. Do not rebuild from `RequestURI`, `EscapedPath`, or AppSec forwarded URI. Host is not in the path. Query is not in the path.
- Headers: compile names with `textproto.CanonicalMIMEHeaderKey`. AND across names. Empty pattern means the header is present. Otherwise RE2 against each value; one hit is enough. Use `req.Header[canonical]`, not `Header.Get`.
- Cookies: same predicate shape; names are case-sensitive. Parse the Cookie header once per request only when this Set has a cookie predicate.
- Reject a fully empty rule (path, headers, and cookies absent AND method any — omitted, empty after trim, or `.*`). A method-only rule is valid.
- Invalid RE2 on method, path, header, or cookie fails `New`.

## Pattern snippet

```go
set, err := httprule.New([]httprule.Rule{{Path: "^/healthz$"}})
if err != nil {
	return nil, err
}
if set.Match(httpReq) {
	return
}
```

## Key files

- `pkg/httprule/rule.go`
- `pkg/httprule/set.go`
- `pkg/configuration/configuration.go` (`BouncerAppsecBypassRules`, `BouncerLapiBypassRules`)
- `pkg/bouncer/bouncer.go` (`appsecBypassRules`, `lapiBypassRules`)

## Gotchas

- Unanchored `health` matches `/unhealthy`. Operators who want an exact path write `^/health$`.
- Method `^post$` does not match `POST`. Write `(?i)` or `^POST$`.
- `example.com://health` does not match path `/health`.
- Empty lists pass `New` and match nothing. A list with one fully empty rule fails.
- `ValidateParams` calls `New` and discards the set; `bouncer.New` compiles again to store it (`core_plugin_middleware_config-validation.md`).
