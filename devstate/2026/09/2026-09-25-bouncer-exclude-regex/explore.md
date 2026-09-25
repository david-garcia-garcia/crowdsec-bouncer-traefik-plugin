# Explore

## Concepts

Operators need a per-router, per-leg skip of CrowdSec LAPI or AppSec on one host+path. Dest has no public regex for that. Trusted IPs skip both legs. Forced header `b` skips lookup. AppSec still `Query`s every pass-path request.

Upstream https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/393 is citation-only for this run's delivery card (maxlerebourg/crowdsec-bouncer-traefik-plugin, "[FEATURE] Exclude host+path routes from the AppSec query"). It is not a second product ask. Do not adopt its location-list / `EXCLUDE_LOCATION`.

### Reproduce

**Verified dest gap (not a runtime crash).** The exclude surface does not exist, so no request path was run against it.

- Grep of worktree `*.go` / `*.md` / `*.yml` for `BouncerAppsecExcludeRegex`, `BouncerLapiExcludeRegex`, `bouncerAppsecExcludeRegex`, `bouncerLapiExcludeRegex`: **not found** outside `devstate/` (requirement + ticket).
- `pkg/configuration/configuration.go` `Config` `bouncer*` block ends at failure actions, trusted IPs, remap, Redis fail-closed, remediation header, startup block — no exclude strings. `New()` defaults those missing fields are absent.
- `pkg/bouncer/bouncer.go` `New` copies request policy and does not compile a path regex. `ServeHTTP`: trusted IPs skip LAPI and AppSec (`next` directly); otherwise a subscribed LAPI leg always `LookupRemediation` / `LiveLookup`; `handleNextServeHTTP` always `applyAppsecServeHTTP` → `Query` when subscribed.
- `pkg/appsec/query.go` `newAppsecForwardRequest` sets `X-Crowdsec-Appsec-Host` from `httpReq.Host` (port may remain) and `X-Crowdsec-Appsec-Uri` from `httpReq.URL.String()` (query may remain). Listener metadata, not an exclude gate.
- `pkg/lapi/identity.go` `ownership` / `pkg/appsec/session.go` `identity` do not hash bouncer exclude regexes.

### Today

```
ServeHTTP
  ├─ !enabled → next
  ├─ startupBlock missing subscribed backend → 503
  ├─ GetRemoteIP → clientRequest (ip owner)
  ├─ trusted client → next (skips LAPI and AppSec)
  ├─ forced header b → ban (no lookup)
  ├─ subscribed LAPI missing → LAPI failure action
  ├─ !subscribeLAPI → passOrForcedCaptcha
  ├─ live|stream|alone → LookupRemediation (store)
  │     active → remediate
  │     no-ban → passOrForcedCaptcha
  ├─ stream|alone miss → StreamHealthy? pass : LAPI failure action
  └─ live|none → LiveLookup → remediate or pass
        │
        ▼
passOrForcedCaptcha
  ├─ forced c → captcha
  └─ handleNextServeHTTP
        ├─ subscribeAppSec → applyAppsecServeHTTP → Query
        └─ next
```

```
  Traefik Host / URL.Path ----+
                              |
  Config (public strings) --> ValidateParams --> bouncer.New (compile) --> ServeHTTP skip
                              |                      |
                              x                      x
                         lapi ownership         appsec identity
                         (out of scope)         (out of scope)
```

| Unit | Path | Job |
| --- | --- | --- |
| Config | `pkg/configuration/configuration.go` `Config` | Public Traefik knobs. Alphabetical by json tag. Request-policy `bouncer*` block. |
| Config validation | `pkg/configuration/configuration.go` `ValidateParams` | Constructor gate before `lapi.Prepare`. Invalid strings fail `plugin.New`. |
| Plugin New | `plugin.go` `New` | Snapshot → `ValidateParams` → Prepare/Open → `bouncer.New`. |
| Bouncer | `pkg/bouncer/bouncer.go` `New` / `ServeHTTP` | Per-router handler. Owns request policy. Compiles nothing today. |
| Pass path | `pkg/bouncer/bouncer.go` `handleNextServeHTTP` / `applyAppsecServeHTTP` | AppSec `Query` then origin. |
| clientRequest | `pkg/bouncer/clientrequest.go` | Request plus GetRemoteIP address. Host/path stay on embedded `*http.Request`. |
| GetRemoteIP | `pkg/ip` | Owner of **client address**, not Host. |
| RequestDomain | `pkg/captcha/captcha.go` | Hostname for **template display**. SplitHostPort strip; empty → `"This site"`. Wrong job for match. |
| AppSec forward | `pkg/appsec/query.go` | Listener Host/URI may keep port and query. Not an exclude gate. |
| LAPI ownership | `pkg/lapi/identity.go` | Open key. Must not grow exclude regexes (Out of scope). |
| AppSec identity | `pkg/appsec/session.go` | Same. |
| Live spec | `openspec/specs/core_plugin_middleware_bouncer/spec.md` | Request policy: trusted IPs, ban/captcha pages, AppSec on pass, LAPI failure action, Redis fail-closed, live-cache TTL. No host+path exclude. |
| Usage | `knowledge/devdocs/core_plugin_middleware.md` | How New reclaims and Bouncer applies request policy. |
| Operator knobs | `README.md` | Documents failure actions, not exclude regexes. |

### Call sites (bounded)

| Contract | Count | Roots searched |
| --- | --- | --- |
| `ValidateParams(` production | **1** (`plugin.go` `New`) | `plugin.go`, `pkg/configuration/configuration.go` |
| `bouncer.New(` production | **1** (`plugin.go` `New`) | `plugin.go` |
| `New(next` in `pkg/bouncer` (tests) | **5** (`zzz_http_timeout_test.go` 1, `zzz_bouncer_test.go` 2, `zzz_ban_template_test.go` 2) | `pkg/bouncer` |
| `Bouncer.ServeHTTP` definition | **1** (`pkg/bouncer/bouncer.go`) | `pkg/bouncer/bouncer.go` |
| `handleNextServeHTTP` production | **3** (`passOrForcedCaptcha`; captcha custom-resource; captcha gate pass) | `pkg/bouncer/bouncer.go` |
| `applyAppsecServeHTTP` production | **1** (`handleNextServeHTTP`) | `pkg/bouncer/bouncer.go` |
| `LookupRemediation` / `LiveLookup` on request path | **1** `ServeHTTP` each | `pkg/bouncer/bouncer.go` |
| Exclude field names | **0** in product tree | `*.go`, `*.md`, `*.yml` excluding `devstate/` |

Empty default means existing callers keep working (additive). No migration of those sites.

### Outside facts

- In-tree: `knowledge/devdocs/core_plugin_middleware.md` (Bouncer, Failure action, two configuration axes), `core_plugin_middleware_config-validation.md` (ValidateParams gate), `core_plugin_appsec.md` (Query on pass), `core_plugin_ip.md` (GetRemoteIP owns client address, not Host), `core_plugin_lapi_reclaim-key.md` (ownership key must not grow request-policy knobs), `knowledge/research/std_go_net_ipv6-zone/` (`SplitHostPort` strips `:port`; IPv6 needs brackets).
- Official: Go `regexp` is RE2 ([pkg.go.dev/regexp](https://pkg.go.dev/regexp)). `Compile` returns `(*Regexp, error)`. `MatchString` reports whether the string **contains any match** (unanchored). `MustCompile` is for constants; operator input uses `Compile`.
- Research: no `std_go_regexp` packet. Facts above are from the official page; no new finding written this phase.
- Upstream #393: citation only. Not consumed as desired behavior.

### Language deltas (consume; no packet write)

No hard gap. **Bouncer**, **Failure action**, **Config validation**, **AppSec Client**, **LAPI Client**, **GetRemoteIP**, **clientRequest** already name the units. Ticket “leg” is the existing subscribe axis (LAPI / AppSec). Do not write packets this phase. Do not fold a new term into a vague leaf.

## Decisions

- **Seam:** Public `bouncerAppsecExcludeRegex` and `bouncerLapiExcludeRegex` (one string each, default empty). `ValidateParams` compiles a non-empty trimmed string and fails `New` on invalid RE2. `bouncer.New` compiles once and stores two `*regexp.Regexp` (nil = no exclude). `ServeHTTP` skips that leg when the compiled regex matches the match string. Not AppSec-client or LAPI-client reclaim knobs.
- **Match string:** `{host}/path` = port-stripped `req.Host` + `req.URL.Path` (decoded; empty Path treated as `/`). No scheme, no port, no query. Host owner is Traefik/`net/http` (`Request.Host`). Path owner for matching in this plugin is `req.URL.Path` (same as captcha widget-asset compare). Strip port with `net.SplitHostPort` the way `RequestDomain` does; do **not** call `RequestDomain` (display fallback `"This site"`). Do not use AppSec `X-Crowdsec-Appsec-Host` / `Uri`.
- **LAPI skip:** a match skips the whole LAPI remediation path: `LookupRemediation`, `LiveLookup`, and stream/alone unhealthy failure action. Continue at `passOrForcedCaptcha` (AppSec may still run; forced `c` still applies).
- **AppSec skip:** a match in `handleNextServeHTTP` skips `applyAppsecServeHTTP` and calls `next`.
- **Order:** startup block → GetRemoteIP → trusted-IP skip → forced `b` → **LAPI exclude** → today's LAPI lookup → pass path **AppSec exclude**. Do not change trusted-IP skip, forced-decision headers, or failure-action enums (Out of scope).
- **Regex engine:** `regexp.Compile` + unanchored `MatchString`. Operators who want a full-string match write `^...$`. Case-sensitive unless the operator writes `(?i)`. No POSIX.
- **Identity:** do not hash these strings into `pkg/lapi` or `pkg/appsec` ownership / identity (Out of scope).
- **Live contract:** `openspec/specs/core_plugin_middleware_bouncer` (request policy). Propose also folds `core_plugin_middleware_config-validation` if invalid regex fails `ValidateParams`. Usage `knowledge/devdocs/core_plugin_middleware.md` (+ config-validation if the gate is documented there). README operator knobs. Not `no live contract`.
- **Rejected:** Upstream #393 location-list / `EXCLUDE_LOCATION` (Out of scope). Matching AppSec forwarded Host/URI (port and query remain; not a gate). Putting knobs on LAPI/AppSec clients. Reusing `RequestDomain` as the match builder. Silent-ignore of invalid regex. Skipping only `LiveLookup` (would not skip stream/alone store). Compiling on every request. Changing trusted-IP or forced-decision order.

## Open questions

- Q: Invalid regex: fail `ValidateParams` / `bouncer.New`, or ignore the setting?
  Rank: additive asked — new validation of new Config strings this change creates; Unknowns "Invalid regex: fail ValidateParams / bouncer.New, or ignore the setting"
  Decision: assumed — trim; empty after trim is off (no compile). Non-empty invalid RE2 fails `ValidateParams` and `bouncer.New` so `plugin.New` returns that error. Do not ignore.
  By: explore

- Q: Exact `{host}/path` build from `*http.Request` (which host field, path encoding, leading slash)?
  Rank: additive asked — new match string this change creates; Desired "Match a normalized incoming path `{host}/path` with no scheme, no port, no query string"
  Decision: assumed — `host` is `req.Host` after `net.SplitHostPort` when that succeeds (IPv6 with port loses brackets; bare `[::1]` stays as Host wrote it). `path` is `req.URL.Path` (decoded, no query); empty Path → `/`. Concatenate host + path (`example.com` + `/health` → `example.com/health`). Do not lowercase. Do not use `URL.String()`, `RequestURI`, or `EscapedPath`.
  By: explore

- Q: Who already owns Host (and the path used for matching)?
  Rank: additive asked — Desired names `{host}/path`; commandments require naming the identity owner before reconstructing Host
  Decision: assumed — Host: Traefik/`net/http` already set `http.Request.Host`; reuse `req.Host`. Client address stays `ip.GetRemoteIP` (do not parse Host as an address). Path for matching: `req.URL.Path`, already used by `captcha.IsCustomResourceRequest`. `captcha.RequestDomain` owns template display only. AppSec forwarded Host/URI are listener metadata, not this owner.
  By: explore

- Q: What LAPI exclude does in stream/alone, where the request path does not query LAPI and still consults the store?
  Rank: additive asked — new skip branch this change creates; In-scope "`pkg/bouncer/bouncer.go` — compile at New; skip that leg on ServeHTTP"; Unknowns name stream/alone
  Decision: assumed — skip the whole LAPI leg: do not call `LookupRemediation`, do not apply a store hit, do not take stream-unhealthy failure action. Go to `passOrForcedCaptcha`.
  By: explore

- Q: Whether a match skips only the live/none `LiveLookup` or also `LookupRemediation`?
  Rank: additive asked — same ServeHTTP skip; Unknowns name both functions
  Decision: assumed — skip both. A LAPI exclude that left store lookup in place would still bounce stream/alone on that path.
  By: explore

- Q: Regex engine flags and whether the match is unanchored `MatchString`?
  Rank: additive asked — new compile/match this change creates; Desired "Each is one string"; Unknowns name flags and MatchString
  Decision: assumed — Go `regexp` (RE2). `Compile` at startup. Unanchored `MatchString` ([pkg.go.dev/regexp](https://pkg.go.dev/regexp#Regexp.MatchString) — "contains any match"). Operators anchor with `^` / `$`. No extra flags in code; `(?i)` / `(?m)` stay in the operator string when they want them.
  By: explore

- Q: Compile/validate owner: `ValidateParams` vs `bouncer.New` only?
  Rank: additive asked — In-scope names public fields on `configuration.go` and "compile at New"; Unknowns name both owners
  Decision: assumed — both. `ValidateParams` compiles a non-empty trimmed string and returns the `Compile` error (constructor gate; discard the value). `bouncer.New` compiles again and stores the `*regexp.Regexp` on the Bouncer. Empty stays nil. Do not compile on the request path.
  By: explore

- Q: Where does the skip sit relative to trusted IPs, forced `b`, and startup block?
  Rank: additive asked — In-scope skip on ServeHTTP; Out of scope "Changing trusted-IP skip, forced-decision headers, or failure-action enums"
  Decision: assumed — after startup block, GetRemoteIP, trusted-IP skip, and forced `b`. Exclude does not override those. Forced `c` still applies on the pass path after a LAPI exclude.
  By: explore
