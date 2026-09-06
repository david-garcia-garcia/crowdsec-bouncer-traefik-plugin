Developer review: in progress — 2026-09-06T15:09:10Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None.

**End users.** None.

## Motivation
On `master`, AppSec JSON `action: captcha` is parsed and relayed but no test proves it. Upstream #357 reports missing captcha support; without proof tests, a regression could restore that gap without CI catching it.

## Merge readiness
Explore complete; propose is next. 6 workflow items remain.

Priority: P3 — tests and spec clarity; no current operator or end-user harm if behavior is already correct.
Reviewed head: 8e5de71
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Explore written; CI still running; no product tests yet |
| CI proof | 3/6 | In progress — [run 34041376450](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041376450) |
| Local tests proof | N/A | Before implement |
| Review resolution | N/A | No PR comments inventoried |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-upstream-357-appsec-captcha-action pushed | git push |
| OpenSpec | none | openspec/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/44 | pr-host |
| CI | in progress [run 34041376450](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041376450) | GitHub check runs queued |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | comments.md absent |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local upstream #357 assessment → branch `2026-09-06-upstream-357-appsec-captcha-action` → stub PR #44 → explore locked add-tests on existing `core_plugin_appsec_bot-detection` → propose next.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Should empty-body AppSec `action: captcha` ban like empty `challenge`, or relay status with no body? | assumed — keep current relay (`handleAppsecResponseServeHTTP`); tests assert `http_status` (403 in the upstream example) and empty body, not the operator ban page. | explore |
| Fold captcha scenarios onto `core_plugin_appsec_bot-detection` or create a new spec? | assumed — MODIFIED on `core_plugin_appsec_bot-detection` (add parse + relay scenarios for `action: captcha`, including the no-body envelope). No new leaf. | explore |

## Before merge
- [ ] [P3] Propose OpenSpec change on `core_plugin_appsec_bot-detection` with captcha parse and relay scenarios
- [ ] [P3] Add captcha JSON parse and bouncer relay tests (including empty-body envelope)
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
| Specs in this PR | none | No product diff yet |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | No comments on stub PR |
| Reviewed head | 8e5de71a797afa3711d24c26a93c150bf1282157 | Matches pushed explore commit |

### Stored data model
None.

### Technical review
Best possible solution: not evaluated — no apply yet.

Do we have a high-confidence way to reproduce? Yes — mirror challenge fixtures in `pkg/appsec/query_test.go` and `pkg/bouncer/bouncer_test.go` with `{"action":"captcha",...}` and the no-body upstream example.

Is this the best way to solve the issue? Yes for scope — add-tests only; product already parses and relays captcha HTML, distinct from `pkg/captcha`.

### Evidence
What I checked:
- `pkg/appsec/query.go` `ActionCaptcha` + `parseResponse`; `pkg/bouncer/bouncer.go` `applyAppsecServeHTTP` fall-through (HEAD 8e5de71)
- Existing challenge tests only: `Test_appsecQuery_challengeJSON`, `TestHandleNextServeHTTPRelaysStructuredAppsecChallenge`
- `openspec/specs/core_plugin_appsec_bot-detection/spec.md` relay requirement already covers non-allow/non-ban actions
- Research already answers protocol: `knowledge/research/ext_crowdsec_appsec_protocol/`, `knowledge/research/ext_crowdsec_appsec_bot-detection/`

### Rank-up moves
None.
