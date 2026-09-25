# Request bypass rules (local)

IssueKey: 2026-09-25-request-bypass-rules
issueHost: local
issueRef: none

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
