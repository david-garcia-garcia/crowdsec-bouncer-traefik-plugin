## Motivation
ServeHTTP already skips CrowdSec at two sites after trusted-IP skip and forced `b`: the LAPI decision path (`LookupRemediation`, `LiveLookup`, missing-LAPI failure, stream-unhealthy failure) and the AppSec hop (body buffer and Query). The knobs for those skips are `bouncerLapiExcludeRegex` and `bouncerAppsecExcludeRegex`: one unanchored RE2 each, compiled by `CompileExcludeRegex`, matched against a reconstructed `host://path`. Host is `req.Host` after `SplitHostPort` when that call succeeds; path is `req.URL.Path` with one leading `/` stripped (empty or `/` becomes `host://`). Example: Host `example.com` Path `/health` → `example.com://health`. Those two strings landed the same day as this ticket.

An operator who needs to skip one leg cannot say it as method, path, headers, and cookies. A `GET /healthz` probe with `X-Health: ok`, an `OPTIONS` preflight, or a cookie-gated path has no authoring form. `health` only matches if that substring appears in `host://path`; it does not mean Path `/unhealthy`. `example.com://health` is the match text, not `/health`. Method is not a predicate. Header and cookie maps do not exist. The two legs can already skip independently, but only through that same host+path string. There is no mock or real e2e that Traefik decodes those knobs and that a banned IP on a matching path reaches origin.

Left alone, `host://path` freezes as the public skip contract. Probe and health traffic that should skip LAPI still takes a store ban or live lookup; AppSec still buffers and queries paths that should skip the hop. Operators keep writing host-qualified patterns that cannot name a header or a cookie. Nothing proves the skip through a Traefik file-provider load.

Priority: P2 — real operator pain, with a workaround or limited blast radius

## Implementation
Replace the two exclude strings with `bouncerAppsecBypassRules` and `bouncerLapiBypassRules` (`[]httprule.Rule`). Compile-once lives in `pkg/httprule` (stdlib only): `New` rejects invalid RE2, `!!`, a leading `!` with no pattern, and a rule whose every predicate is any (`{}` or `{method: ".*"}`); a method-only rule is valid. `ValidateParams` calls `New` so `plugin.New` fails before LAPI Open (error names the Go field); `bouncer.New` compiles again and stores `*httprule.Set`. Request check is `Set.Match`: OR across rules, first wins; AND method → path → headers → cookies. Method and path are unanchored RE2 on `req.Method` and `req.URL.Path`; optional leading `!` negates method; the plugin does not insert `^`/`$` or fold case. Headers use `CanonicalMIMEHeaderKey`; cookies are case-sensitive; Cookie is parsed once per request only when that set has a cookie predicate.

ServeHTTP keeps the exclude skip sites: after forced `b`, a LAPI match goes to `passOrForcedCaptcha`; in `handleNextServeHTTP`, an AppSec match calls `next` with no buffer and no Query. Trusted-IP, forced `b`, and startup-block 503 still run first. `recordProcessed` stays where it is. Bypass lists stay off reclaim keys. `CompileExcludeRegex`, `excludeMatchString`, and `excludedBy` are deleted. Mock e2e `request-bypass-rules` proves Traefik nested-list decode, LAPI skip of a banned IP on `/healthz`, AppSec skip of mock `rpc2` on `/foo/403-skip`, and independence.

## What this changes
**Operators.** **BREAKING:** drop `bouncerAppsecExcludeRegex` / `bouncerLapiExcludeRegex` (leftover YAML is ignored) and author `bouncerAppsecBypassRules` / `bouncerLapiBypassRules`; path is unanchored RE2 on `req.URL.Path` so `health` matches `/unhealthy`.
**Admin users.** None.
**Developers.** Public Config replaces the two exclude strings with `BouncerAppsecBypassRules` / `BouncerLapiBypassRules` (`[]httprule.Rule`); `CompileExcludeRegex` is removed; `httprule.New` / `Set.Match` is the compile-and-match contract, and the lists stay off reclaim keys.
**End users.** None.

## Merge readiness
In progress. 0 items remain.

Priority: P2 — real operator pain, with a workaround or limited blast radius
Reviewed head: adeb6635
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Not ready |
| CI proof | 1/6 | not seen |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-25-request-bypass-rules pushed | `git` |
| OpenSpec | request-bypass-rules | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/163 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-request-bypass-rules/openspec/changes/request-bypass-rules/proposal.md) — modified
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-request-bypass-rules/openspec/changes/request-bypass-rules/proposal.md) — modified


## Deviations from the ask
- taken: method is a case-insensitive HTTP method token; a block with no path, no headers, and no cookies (method-only or nothing) fails plugin construction. → method is unanchored Go RE2 on `req.Method` with optional leading `!`; no silent case-fold and no forced `(?i)`. A method-only rule is valid. Construction fails only when path, headers, and cookies are absent AND method is any (omitted, empty, or a match-everything pattern such as `.*`). — `pkg/httprule` — honouring an exact case-insensitive token would add a second match family beside path RE2; treating a set method predicate as fully empty would reject `method: ^OPTIONS$`. Human correction already resolved method as RE2 same family as path.. Requester: confirmed.


## Follow-up issues
None.

## How this fits together
Ticket 2026-09-25-request-bypass-rules on branch 2026-09-25-request-bypass-rules targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/163; CI not seen.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Where does the matcher package live under pkg/? | additive asked — new package this change creates; criterion Implement the matcher as its own package | assumed — pkg/httprule. Authoring type Rule with json method, path, headers, cookies. Compiled Set. No imports of this plugin. | explore |


## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-request-bypass-rules/devstate/2026/09/2026-09-25-request-bypass-rules/codereview_standards.md) — 2 total, 0 pending, 1 completed, 1 skipped
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-request-bypass-rules/devstate/2026/09/2026-09-25-request-bypass-rules/codereview_nitpicks.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-request-bypass-rules/devstate/2026/09/2026-09-25-request-bypass-rules/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-request-bypass-rules/devstate/2026/09/2026-09-25-request-bypass-rules/codereview_scope.md) — 2 total, 0 pending, 0 completed, 2 skipped
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-request-bypass-rules/devstate/2026/09/2026-09-25-request-bypass-rules/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-request-bypass-rules/devstate/2026/09/2026-09-25-request-bypass-rules/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-request-bypass-rules/devstate/2026/09/2026-09-25-request-bypass-rules/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-request-bypass-rules/devstate/2026/09/2026-09-25-request-bypass-rules/codereview_coverage.md) — 3 total, 0 pending, 2 completed, 1 skipped


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 2 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | adeb66352decc1e7e37dd87bf841a3e36bdfd60b | Card must match the branch you measured |

### Stored data model
None.
