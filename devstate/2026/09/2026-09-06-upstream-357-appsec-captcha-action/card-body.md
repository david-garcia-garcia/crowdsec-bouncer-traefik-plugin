Developer review: in progress — 2026-09-06T15:12:35Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** OpenSpec change `appsec-captcha-action-tests` adds captcha parse and relay scenarios on `core_plugin_appsec_bot-detection`; product tests are not landed yet.

**End users.** None.

## Motivation
On `master`, AppSec JSON `action: captcha` is parsed and relayed but no test or spec scenario names that envelope. Upstream #357 reports missing captcha support; without proof, a regression can restore that gap without CI catching it.

## Merge readiness
Propose complete; implement is next. 5 workflow items remain.

Priority: P3 — tests and spec clarity; no current operator or end-user harm if behavior is already correct.
Reviewed head: 13be452
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Proposal apply-ready; CI still running; tests not landed |
| CI proof | 3/6 | In progress — [run 34041570407](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041570407) |
| Local tests proof | N/A | Before implement |
| Review resolution | N/A | No PR comments inventoried |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-upstream-357-appsec-captcha-action pushed | git push |
| OpenSpec | appsec-captcha-action-tests | openspec/changes/appsec-captcha-action-tests/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/44 | pr-host |
| CI | in progress [run 34041570407](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041570407) | GitHub check runs queued |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | comments.md absent |

## Specs
- [core_plugin_appsec_bot-detection](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-357-appsec-captcha-action/openspec/changes/appsec-captcha-action-tests/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
Local upstream #357 assessment → branch `2026-09-06-upstream-357-appsec-captcha-action` → stub PR #44 → OpenSpec `appsec-captcha-action-tests` → implement next.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Should empty-body AppSec `action: captcha` ban like empty `challenge`, or relay status with no body? | assumed — keep current relay (`handleAppsecResponseServeHTTP`); tests assert `http_status` (403 in the upstream example) and empty body, not the operator ban page. | explore |
| Fold captcha scenarios onto `core_plugin_appsec_bot-detection` or create a new spec? | assumed — MODIFIED on `core_plugin_appsec_bot-detection` (add parse + relay scenarios for `action: captcha`, including the no-body envelope). No new leaf. | explore |

## Before merge
- [ ] [P3] Add captcha JSON parse and bouncer relay tests (including empty-body envelope)
- [x] Propose OpenSpec change `appsec-captcha-action-tests` on `core_plugin_appsec_bot-detection`
- [x] Explore: empty-body captcha stays relay; lock envelope parse+relay not `pkg/captcha`
- [x] Prepare: requirement, worktree, stub PR

## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 1 modified | Same list as Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | No comments on stub PR |
| Reviewed head | 13be452d03d0f4ef00d5f4a55c818be68d915fc2 | Matches pushed propose commit |

### Stored data model
None.

### Technical review
Best possible solution: not evaluated — apply not started.

Do we have a high-confidence way to reproduce? Yes — tasks name fixtures in `pkg/appsec/query_test.go` and `pkg/bouncer/bouncer_test.go`.

Is this the best way to solve the issue? Yes for scope — fold onto existing bot-detection spec; add-tests only.

### Evidence
What I checked:
- `openspec validate appsec-captcha-action-tests --strict` passed
- FindSpecHost fold `core_plugin_appsec_bot-detection` (HEAD 13be452)
- Product Go files unchanged vs `origin/master` in this PR

### Rank-up moves
None.
