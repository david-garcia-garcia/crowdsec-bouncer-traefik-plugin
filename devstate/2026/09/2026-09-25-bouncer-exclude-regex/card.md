## Motivation
Operators bounce a Traefik router through CrowdSec LAPI and AppSec. Request policy already has trusted client IPs (skip the whole plugin), a forced decision header, and per-leg failure actions. It has no public regex that excludes one CrowdSec leg for a host+path.

A bouncing router that also serves a probe at host `example.com` path `/health` still consults LAPI (stream/alone store, live/none lookup, missing-LAPI and stream-unhealthy failure) and still AppSec-queries on the pass path. AppSec already forwards Host and URI as listener metadata; that is not a skip. Trusted IPs skip both legs, so the only workaround is to trust the client and drop LAPI and AppSec together. There is no way to skip only AppSec or only LAPI on that path while still bouncing the rest of the router.

https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/393 is citation only for this card, not a second product ask.

Left alone, probe and static paths on a bouncing router keep paying both CrowdSec legs, or the operator has to disable bouncing for those clients entirely.

Priority: P2 — real operator pain, with a workaround (trusted IPs skip both legs)

## Implementation
Two additive Config strings `bouncerAppsecExcludeRegex` and `bouncerLapiExcludeRegex` (empty after trim is off). `ValidateParams` compiles a non-empty trimmed string as Go RE2 and fails `plugin.New` with a nil handler before LAPI open. `bouncer.New` compiles again and stores two `*regexp.Regexp` (nil is off). ServeHTTP matches unanchored `MatchString` against host + `://` + path with the leading slash removed once: `req.Host` after `net.SplitHostPort` when that succeeds, then literal `://`, then `req.URL.Path` with one leading `/` stripped (`example.com://health`; root `example.com://`; not `example.com/health` and not `example.com:///health`). After trusted IPs and forced `b`, a LAPI match skips the whole LAPI remediation path and continues at `passOrForcedCaptcha` (AppSec may still run; forced `c` still applies). An AppSec match in `handleNextServeHTTP` skips Query and calls next. The strings stay off LAPI ownership and AppSec identity.

## What this changes
**Operators.** Set `bouncerAppsecExcludeRegex` and/or `bouncerLapiExcludeRegex` on the bouncing router: a RE2 match against `host://path` (`example.com://health`, root `example.com://`) skips that CrowdSec leg; empty is off; invalid pattern fails New; write `^...$` to anchor; exclude does not override trusted IPs, forced `b`, or startup block.
**Admin users.** None.
**Developers.** Public Config JSON keys and exported `CompileExcludeRegex`; match string is port-stripped Host + `://` + decoded Path with one leading slash removed; exclude strings are not in LAPI ownership or AppSec identity.
**End users.** None.

## Merge readiness
In progress. 0 items remain.

Priority: P2 — real operator pain, with a workaround (trusted IPs skip both legs)
Reviewed head: f95ac4e7
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
| Branch | 2026-09-25-bouncer-exclude-regex pushed | `git` |
| OpenSpec | bouncer-exclude-regex | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/158 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-bouncer-exclude-regex/openspec/changes/bouncer-exclude-regex/proposal.md) — modified
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-bouncer-exclude-regex/openspec/changes/bouncer-exclude-regex/proposal.md) — modified


## Deviations from the ask
None.

## Follow-up issues
None.

## How this fits together
Ticket 2026-09-25-bouncer-exclude-regex on branch 2026-09-25-bouncer-exclude-regex targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/158; CI not seen.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Is upstream https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/393 a second product requirement? | additive asked — Problem "Upstream https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/393 is citation-only for this run's delivery card, not a second product ask" | assumed — no. Citation only (maxlerebourg/crowdsec-bouncer-traefik-plugin#393). Do not adopt location-list / EXCLUDE_LOCATION. Remaining assumed rows stay on explore.md. | explore |


## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-bouncer-exclude-regex/devstate/2026/09/2026-09-25-bouncer-exclude-regex/codereview_standards.md) — 0 total, 0 pending, 0 completed
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-bouncer-exclude-regex/devstate/2026/09/2026-09-25-bouncer-exclude-regex/codereview_nitpicks.md) — 2 total, 0 pending, 2 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-bouncer-exclude-regex/devstate/2026/09/2026-09-25-bouncer-exclude-regex/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-bouncer-exclude-regex/devstate/2026/09/2026-09-25-bouncer-exclude-regex/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-bouncer-exclude-regex/devstate/2026/09/2026-09-25-bouncer-exclude-regex/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-bouncer-exclude-regex/devstate/2026/09/2026-09-25-bouncer-exclude-regex/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-bouncer-exclude-regex/devstate/2026/09/2026-09-25-bouncer-exclude-regex/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-bouncer-exclude-regex/devstate/2026/09/2026-09-25-bouncer-exclude-regex/codereview_coverage.md) — 1 total, 0 pending, 1 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 2 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | f95ac4e7e56c5a095c25f93b932d188b6ca64d49 | Card must match the branch you measured |

### Stored data model
None.
