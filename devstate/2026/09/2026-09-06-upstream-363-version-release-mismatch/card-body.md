Developer review: in progress — 2026-09-06T15:17:06Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** OpenSpec change `assert-plugin-version-reporting` folds version-reporting scenarios into `core_plugin_lapi_usage-metrics` and `core_plugin_appsec_client`. Tests are not landed yet.

**End users.** None.

## Motivation
On `master`, `cscli bouncers list` can show a stale plugin version if a tag ships while `version.go` still names the previous release (upstream #322 and #363). This fork already bumps `version.go` before tagging, and the tree currently reports `v1.7.1`, but no test asserts usage-metrics `remediation_components[].version` or `User-Agent: Crowdsec-Bouncer-Traefik-Plugin/<version>`. Without those tests, a future manual release bypass can regress undetected.

## Merge readiness
Propose complete; implement next. Product tests not yet in the apply.

Priority: P3 — spec, docs, tests, or internal clarity — no current user or operator harm
Reviewed head: d7d2b7a
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | E2E still running; tests not applied |
| CI proof | 3/6 | Main Process succeeded; e2e in progress on [run 34041629723](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041629723) |
| Local tests proof | N/A | Before implement; remote PR uses CI proof |
| Review resolution | 6/6 | No open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-upstream-363-version-release-mismatch pushed | git push d7d2b7a |
| OpenSpec | assert-plugin-version-reporting | openspec/changes/assert-plugin-version-reporting |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/53 | GitHub #53 |
| CI | build 34041629723 in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041629723 | pull_request_read get_check_runs |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | comments: none |

## Specs
- [core_plugin_lapi_usage-metrics](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-363-version-release-mismatch/openspec/changes/assert-plugin-version-reporting/proposal.md) — modified
- [core_plugin_appsec_client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-363-version-release-mismatch/openspec/changes/assert-plugin-version-reporting/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
Local add-tests ticket for upstream #322+#363 → OpenSpec change `assert-plugin-version-reporting` on stub PR #53 → implement will land httptests.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Which seam proves `version.go` is what LAPI/cscli would record, without exporting `pluginVersion`? | assumed — pkg/lapi httptest with an injected distinctive version proves the Client copies version into JSON and User-Agent; a root-package `New` test asserts that User-Agent uses the unexported `pluginVersion` from `version.go`. AppSec Query httptest covers the sibling User-Agent. Do not export the var. | explore |
| Does a static `version.go` vs git-tag or workflow-YAML test add value? | assumed — no. Unit tests have no release tag. `release-publish.yml` already exits 1 when commit message and `version.go` disagree. Bound is add-tests, not workflow edits. | explore |
| Should `NewTestClient` grow a version argument? | assumed — set `pluginVersion` on the Client in the new AppSec test. Change `NewTestClient` only if the field cannot be set from `query_test.go` (same package: it can). | explore |

## Before merge
- Land httptest coverage for usage-metrics `version` and LAPI/AppSec User-Agent [P3]
- CI succeeded on the product commits

## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 2 modified | Same list as Specs |
| Open reviewer comments walked | 0 | No PR comments |
| Reviewed head | d7d2b7aff7532511c99b26a281ec8b8502688ec7 | Card matches latest push |

### Stored data model
None.

### Technical review
Best possible solution: fold scenarios into existing usage-metrics and AppSec specs; prove with httptest; no runtime change versus `master`.

Do we have a high-confidence way to reproduce? No for the runtime stale-tag symptom (`version.go` already reads `v1.7.1`). Yes for the test gap.

Is this the best way to solve the issue? Yes versus `master` — bound is add-tests.

### Evidence
What I checked:
- `openspec/changes/assert-plugin-version-reporting/` (proposal, specs, design, tasks)
- `openspec validate assert-plugin-version-reporting` valid, 4/4 artifacts
- CI check_runs on PR #53 after d7d2b7a

### Rank-up moves
None.
