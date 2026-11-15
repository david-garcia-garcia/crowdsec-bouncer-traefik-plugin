## Motivation
CrowdSec 1.8 bot detection answers a suspicious request with a JavaScript challenge page. The page then calls back to URLs under `/crowdsec-internal/challenge/`: it loads `fpscanner.js` and `pow-worker.js`, and POSTs the proof to `/crowdsec-internal/challenge/submit`. Those calls must go through the bouncer so AppSec can answer them. The fork's upstream review found four problems around that prefix and the action rules that can skip AppSec.

| Fork review problem | Priority | Upstream |
| --- | --- | --- |
| 2. An unanswered request under the challenge prefix reached origin | P1 | issue https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/402, PR https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 point 4 |
| 5. One challenge solve counted as about four drops | P2 | PR https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 point 5 |
| 7. A broad `bypassAppsec` rule made the challenge unsolvable | P2 | issue https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/393, PR https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/413 |
| 8. `bypass*` path rules matched paths with more than one reading | P2 | PR https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/413 (single-reading rule of `crowdsecAppsecExcludedLocations`) |

No upstream patch was copied: upstream edits its root `bouncer.go` and `pkg/location`, and this fork has `bouncerActionRules`.

- **Problem 2.** When AppSec was in use and nothing answered a prefix request (AppSec allow, failure-action passthrough, a cleared captcha gate), the request was forwarded to the router's service. Measured on CrowdSec 1.8.2 on 2026-11-15: with no challenge cookie AppSec answers every prefix path itself, so this only happens once the visitor holds a valid `__crowdsec_challenge` and asks for a prefix path CrowdSec does not serve. It is defence in depth, not an observed leak on 1.8.2. Folded in from https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/196 (closed as superseded).
- **Problem 5.** Every relayed AppSec envelope was a usage-metrics drop (request and bytes), so the page plus its scripts and submit counted several times for one solve, and the drop figures overstated what was blocked.
- **Problem 7.** A `bypass` / `bypassAppsec` action rule that matched challenge paths (for example `\.js$`) skipped AppSec there. Reproduced on Traefik v3.7.11: `fpscanner.js` and `custom.js` reached the origin whoami, so the challenge could never be solved.
- **Problem 8.** A `bypass*` path rule matched the decoded path even when the request path had more than one reading. Measured on Traefik v3.7.11 with an anchored `^/healthz(/|$)` `bypassAppsec` rule: `/healthz/..;/admin`, `/healthz/%2E%2E;/admin`, `/healthz/..%5Cadmin`, `/healthz%2Fadmin` and `/healthz/%252e%252e/admin` skipped AppSec and reached origin unchanged, where a backend such as a Java servlet container can resolve them to `/admin`.

Priority: P1 — unanswered challenge paths can reach origin, and bypass rules can let ambiguous paths skip AppSec; the metrics over-count is P2.

## Implementation
All four parts sit in `pkg/bouncer/bouncer.go` and `pkg/httprule`, and the prefix has one owner: `crowdsecChallengeCallbackPrefix` / `isCrowdsecChallengeCallbackPath`.

- **Metrics (problem 5).** `handleAppsecResponseServeHTTP` still writes the envelope but skips `recordDropped` under the prefix, so neither the request nor the byte series moves. The challenge page, bans, the captcha gate and other relays count as before. The metrics POST shape is unchanged.
- **404 (problem 2).** `serveAppSec` runs the previous logic as `answerAppSec`. When nothing wrote, AppSec is in use for the request and the path is under the prefix, it writes `http.NotFound` and returns true, so `next` is not called. A challenge, captcha or ban envelope is still written first. The captcha-form gate from #206 runs before the 404.
- **Challenge prefix keeps AppSec (problem 7).** `foldActionRules` clears `SkipAppsec` under the prefix, so no action rule can skip AppSec there. The LAPI skip stays. This reverses the PR 196 explore decision "SkipAppsec still calls next", which `explore.md` marks.
- **Single-reading paths (problem 8).** `httprule.SingleReadingPath`, applied in `Fold`, rejects a path when any of these is true: `Path != EscapedPath`, it has bytes outside `A-Za-z0-9-._~!$&'()+,=:@/`, `path.Clean` changes it, or it has a dots-only segment. For such a path, a row with a path predicate contributes no skip, but its captcha token still applies. Rows without a path and ban rows are unchanged. `ActionMatch.AmbiguousPathName` is logged at TRACE.
- **Tests.**
  - Go unit tests cover dropped counts, all the 404 cases and the action-rule folds.
  - The mock e2e scenario `request-bypass-rules` (Traefik v3.7.11 binary, yaegi) asserts the `..;` variant is still inspected.
  - A real CrowdSec 1.8.2 Pester context covers the challenge page, the relayed scripts and submit, a granted cookie reaching origin, the 404 on an allowed prefix path, and one drop per solve.
  - The fixes were disabled in turn to check the tests: 2 Pester cases, 4 unit tests and the e2e `..;` assertion fail.
- **Merge and docs.** Master was merged in (#191, #194, #198, #201, #206, #207, #208, #209). Each OpenSpec delta was rebuilt on master's text, so archiving does not revert #206. The README and the devdocs `core_plugin_appsec`, `core_plugin_httprule`, `core_plugin_middleware_action-rules`, `core_plugin_lapi_usage-metrics` and `build_e2e_real` were updated.

## What this changes
**Operators.**
- One solved challenge is one usage-metrics drop.
- A `bypass` / `bypassAppsec` rule no longer skips AppSec under `/crowdsec-internal/challenge/`.
- A `bypass*` path rule no longer skips a request whose path is percent-encoded (for example `%20`) or carries `;`, `\`, `*`, dot or empty segments; those requests are inspected. No configuration change.

**Admin users.** None.

**Developers.**
- Under `/crowdsec-internal/challenge/` AppSec is the only owner: action rules cannot skip it, an unanswered request is 404 and never calls `next`, and a relay there is not a drop.
- `httprule.Fold` only grants a path-rule skip for a single-reading path.

**End users.** A challenge-prefix request nothing answers gets 404 instead of the origin's response, and a challenge behind a broad `\.js$` bypass rule can be solved again.

## Merge readiness
In progress. 1 items remain.

Priority: P1 — unanswered challenge paths can reach origin, and bypass rules can let ambiguous paths skip AppSec; the metrics over-count is P2.
Reviewed head: 52f21152
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
| Branch | 2026-10-13-count-challenge-once pushed | `git` |
| OpenSpec | count-challenge-drop-once | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/197 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_appsec_bot-detection](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/openspec/changes/archive/2026-11-15-action-rule-skips-challenge-and-ambiguous-paths/proposal.md) — modified
- [core_plugin_appsec_bot-detection](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/openspec/changes/archive/2026-11-15-count-challenge-drop-once/proposal.md) — modified
- [core_plugin_appsec_bot-detection](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/openspec/changes/archive/2026-11-15-terminate-unanswered-challenge-paths/proposal.md) — modified
- [core_plugin_appsec_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/openspec/changes/archive/2026-11-15-terminate-unanswered-challenge-paths/proposal.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/openspec/changes/archive/2026-11-15-action-rule-skips-challenge-and-ambiguous-paths/proposal.md) — modified

Completed:
- [core_plugin_appsec_bot-detection](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/openspec/specs/core_plugin_appsec_bot-detection/spec.md) — modified
- [core_plugin_appsec_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/openspec/specs/core_plugin_appsec_failure-action/spec.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/openspec/specs/core_plugin_middleware_bouncer/spec.md) — modified


## Deviations from the ask
None.

## Follow-up issues
- [ ] [Ban and captcha path rules can be evaded by an ambiguous path](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/knowledge/debt/2026-11-15-ban-captcha-path-rules-ambiguous-path-evasion.md) — ban and captcha path rules still match the decoded path, so an ambiguous path the backend resolves into their prefix (for example `/x/..;/admin` vs `^/admin`) evades them.


## How this fits together
Ticket 2026-10-13-count-challenge-once on branch 2026-10-13-count-challenge-once targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/197; CI not seen.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Which request path field implements the challenge-callback prefix? | additive asked — Desired names the path prefix; httprule already matches URL.Path (1 family in pkg/httprule, enumerated with pkg/bouncer/bouncer.go) | assumed — use req.URL.Path with strings.HasPrefix and /crowdsec-internal/challenge/. Traefik ServeHTTP fills URL.Path; do not parse RequestURI. | explore |


## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/devstate/2026/10/2026-10-13-count-challenge-once/codereview_standards.md) — 0 total, 0 pending, 0 completed
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/devstate/2026/10/2026-10-13-count-challenge-once/codereview_nitpicks.md) — 1 total, 0 pending, 1 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/devstate/2026/10/2026-10-13-count-challenge-once/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/devstate/2026/10/2026-10-13-count-challenge-once/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/devstate/2026/10/2026-10-13-count-challenge-once/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/devstate/2026/10/2026-10-13-count-challenge-once/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/devstate/2026/10/2026-10-13-count-challenge-once/codereview_dead.md) — 1 total, 0 pending, 0 completed, 1 skipped
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/devstate/2026/10/2026-10-13-count-challenge-once/codereview_coverage.md) — 1 total, 0 pending, 1 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 8 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 52f21152eb8ed2e18a7bee58aeb0a4a91b8c136e | Card must match the branch you measured |

### Stored data model
None.
