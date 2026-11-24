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
The compiled list `httprule.NewActionSet` returns. Predicate match stays on `Set`; names and tokens sit beside it. `Matching` returns every hit. `Fold` reduces those hits to `ActionMatch`: first ban name, first captcha name, first bypassCaptcha name, OR of the skip flags. A ban row contributes only its name. A set `BypassCaptchaName` clears `CaptchaName`: a request that gets no captcha has no captcha rule. A row with a `path` predicate contributes no skip when `SingleReadingPath(req.URL)` is false; its captcha and bypassCaptcha still count and `AmbiguousPathName` names the first such row.
_Avoid_: interpreting action tokens inside `Set.Match`

## Overview

Compile request exemptions once with `httprule.New`. Config holds `[]ActionRule`; Bouncer stores `*ActionSet`. Predicate compile stays `httprule.New`. The package imports only the Go standard library. `ActionSet.Fold` is the request-level reduction; ServeHTTP remediation stays on `core_plugin_middleware_action-rules.md`. Constructor reject wrapping stays on `core_plugin_middleware_config-validation.md`.

## How to use

- Call `httprule.New` once at construct for predicate-only lists. Call `httprule.NewActionSet` for `bouncerActionRules`. Do not compile on the request path. Store `*Set` or `*ActionSet`. Call `Set.Match(clientrequest.Request)` for first-wins boolean; call `Matching(clientrequest.Request)` when every hit index is needed; call `ActionSet.Fold(clientrequest.Request)` for the reduced `ActionMatch`. A nil `ActionSet` folds to the zero value.
- Call `httprule.NewWithCatchAll` when a row with no predicate must match every request (rate-limit buckets, `core_plugin_ratelimit.md`). It is `New` without the fully-empty-rule reject; invalid RE2 still fails.
- Validate the name of any authoring row (action rule, rate-limit bucket) with `CompileRowName(raw, seen)`: it trims and rejects empty, `:`, and a name already in `seen`. The caller adds the returned name to `seen`.
- Do not import this plugin's other packages from `pkg/httprule`, except `pkg/clientrequest`: the request and its host name (`core_plugin_clientrequest_inbound-request.md`).
- Method: unanchored Go RE2 `MatchString` on `req.Method`. Do not insert `^` or `$`. Do not lowercase. Do not force `(?i)`. Omit or empty after trim is any. Optional single leading `!` (outside the pattern) negates (`!POST`, `!^POST$`). `!!` and `!` with an empty pattern fail `New`.
- Path: unanchored `MatchString` on `req.URL.Path` as `net/http` decoded it. Do not rebuild from `RequestURI`, `EscapedPath`, or AppSec forwarded URI. Host is not in the path. Query is not in the path.
- `SingleReadingPath(*url.URL)`: true only when `Path == EscapedPath()`, every byte is in `A-Z a-z 0-9 - . _ ~ ! $ & ' ( ) + , = : @ /`, `path.Clean` (trailing slash kept) leaves it unchanged, and no segment is dots only. Same criterion as upstream `pkg/location` (PR 413). `Fold` uses it to drop the `bypass`, `bypassLapi`, `bypassAppsec` and `bypassRateLimit` skips; `Set.Match` / `Matching` do not, and neither does the `bypassCaptcha` token.
- Host: unanchored `MatchString` on `req.Hostname()`: lower case, without the port and without one trailing dot (`EXAMPLE.com.:443` → `example.com`, `[::1]:443` → `::1`). Do not split or lower `req.Host` here. Do not force `(?i)`: the value is already lower case, so a lower-case pattern matches, and an upper-case pattern matches only with `(?i)`. Do not read the Host header map. Do not include scheme, port, or path. Omit or empty after trim is any. No leading `!`. A host-only rule is valid.
- Headers: compile names with `textproto.CanonicalMIMEHeaderKey`. AND across names. Empty pattern means the header is present. Otherwise RE2 against each value; one hit is enough. Use `req.Header[canonical]`, not `Header.Get`.
- Cookies: same predicate shape; names are case-sensitive. Parse the Cookie header once per request only when this Set has a cookie predicate.
- `New` and `NewActionSet` reject a fully empty rule (path, host, headers, and cookies absent AND method any — omitted, empty after trim, or `.*`). A method-only or host-only rule is valid.
- Invalid RE2 on method, path, host, header, or cookie fails `New`. The host error names `host`.

## Pattern snippet

```go
set, err := httprule.NewActionSet([]httprule.ActionRule{{Name: "healthz", Action: []string{httprule.ActionBypass}, Rule: httprule.Rule{Path: "^/healthz$"}}})
if err != nil {
	return nil, err
}
match := set.Fold(req)
```

## Key files

- `pkg/httprule/rule.go`
- `pkg/httprule/set.go`
- `pkg/clientrequest/request.go` (`Hostname`)
- `pkg/httprule/action.go`
- `pkg/httprule/path.go` (`SingleReadingPath`)
- `pkg/configuration/configuration.go` (`BouncerActionRules`)
- `pkg/bouncer/bouncer.go` (`actionRules`)

## Gotchas

- Unanchored `health` matches `/unhealthy`. Operators who want an exact path write `^/health$`.
- Anchoring does not stop path confusion: Traefik v3.7.11 forwards `/healthz/..;/admin`, `/healthz/%2E%2E;/admin` (decoded to `..;`) and `/healthz/..%5Cadmin` unchanged, and `^/healthz/` matches them. A Java servlet backend reads `..;` as `..`. That is why `Fold` drops skips on such paths.
- `%20` and other percent-encoding make a path ambiguous too, so a bypass path rule no longer skips those requests. Fail-safe: the leg inspects them.
- `bypassCaptcha` is the exception: its path regex applies as written on every path, by an operator decision that leans on Traefik. Traefik resolves `..`, `%2e%2e` and `\` before the plugin, and `..;` from v3.7.18; it forwards `..%2F`, `..%5C`, `..%3B` and double encoding unless the entry point rejects them (`knowledge/research/ext_traefik_entrypoints_request-path/`). Only a captcha is weakened; bans are not.
- Host match text is the lower-case hostname only. `Example.COM.:443` matches `^example.com$`; `^EXAMPLE` matches nothing unless written `(?i)^EXAMPLE`. `[::1]:443` matches `^::1$`, not `^\[::1\]$`.
- Method, path, header, and cookie patterns are case-sensitive: `^post$` does not match `POST`. Write `(?i)` or `^POST$`. The operator docs tell users to start a pattern with `(?i)` to ignore case.
- `example.com://health` does not match path `/health`.
- Empty lists pass `New` and match nothing. A list with one fully empty rule fails `New`; `NewWithCatchAll` keeps that row as match-all.
- `ValidateParams` calls `NewActionSet` and discards the set; `bouncer.New` compiles again to store it (`core_plugin_middleware_config-validation.md`).
