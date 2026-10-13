Developer review: ready for review — 2026-09-06T15:34:14Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** Tests assert LAPI usage-metrics `remediation_components[].version` and LAPI/AppSec `User-Agent` carry the constructed plugin version, and that `New` uses `version.go` `pluginVersion`. Envelope-identity and AppSec User-Agent scenarios are folded into the main specs. Runtime reporting is unchanged versus `master`.

**End users.** None.

## Motivation
On `master`, `cscli bouncers list` can show a stale plugin version if a tag ships while `version.go` still names the previous release (upstream #322 and #363). This fork already bumps `version.go` before tagging, and the tree currently reports `v1.7.1`, but no test asserted usage-metrics `version` or User-Agent. Without those tests, a future manual release bypass can regress undetected.

## Merge readiness
Ready for review. CI succeeded. No checklist items remain.

Priority: P3 — spec, docs, tests, or internal clarity — no current user or operator harm
Reviewed head: 57f079e
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | CI succeeded; no open comments |
| CI proof | 6/6 | Main Process, e2e mock LAPI, and e2e docker+pester succeeded on [run 34042451573](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34042451573) |
| Local tests proof | N/A | Remote PR uses CI proof |
| Review resolution | 6/6 | No open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-upstream-363-version-release-mismatch pushed | git push 57f079e |
| OpenSpec | assert-plugin-version-reporting (archived) | openspec/changes/archive/2026-09-06-assert-plugin-version-reporting |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/53 | GitHub #53 |
| CI | build 34042451573 success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34042451573 | pull_request_read get_check_runs |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | comments: none |

## Specs
- [core_plugin_lapi_usage-metrics](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-363-version-release-mismatch/openspec/changes/archive/2026-09-06-assert-plugin-version-reporting/proposal.md) — modified
- [core_plugin_appsec_client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-363-version-release-mismatch/openspec/changes/archive/2026-09-06-assert-plugin-version-reporting/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
Local add-tests ticket for upstream #322+#363 → httptests and archived specs on PR #53 with green CI.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Which seam proves `version.go` is what LAPI/cscli would record, without exporting `pluginVersion`? | assumed — pkg/lapi httptest with an injected distinctive version proves the Client copies version into JSON and User-Agent; a root-package `New` test asserts that User-Agent uses the unexported `pluginVersion` from `version.go`. AppSec Query httptest covers the sibling User-Agent. Do not export the var. | explore |
| Does a static `version.go` vs git-tag or workflow-YAML test add value? | assumed — no. Unit tests have no release tag. `release-publish.yml` already exits 1 when commit message and `version.go` disagree. Bound is add-tests, not workflow edits. | explore |
| Should `NewTestClient` grow a version argument? | assumed — set `pluginVersion` on the Client in the new AppSec test. Change `NewTestClient` only if the field cannot be set from `query_test.go` (same package: it can). | explore |

## Before merge
None.

## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-363-version-release-mismatch/devstate/2026/09/2026-09-06-upstream-363-version-release-mismatch/codereview_standards.md) — 2 total, 0 pending, 1 completed, 1 skipped
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-363-version-release-mismatch/devstate/2026/09/2026-09-06-upstream-363-version-release-mismatch/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-363-version-release-mismatch/devstate/2026/09/2026-09-06-upstream-363-version-release-mismatch/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-363-version-release-mismatch/devstate/2026/09/2026-09-06-upstream-363-version-release-mismatch/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-363-version-release-mismatch/devstate/2026/09/2026-09-06-upstream-363-version-release-mismatch/codereview_dead.md) — 0 total, 0 pending, 0 completed

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 2 modified | Same list as Specs |
| Open reviewer comments walked | 0 | No PR comments |
| Reviewed head | 57f079e86aef3068909f25ba7023aff06b67a52d | Card matches latest push |

### Stored data model
None.

### Technical review
Best possible solution: httptest on existing Client and `New` seams; no runtime change versus `master`.

Do we have a high-confidence way to reproduce? Yes for the test gap — three httptests landed and CI passed.

Is this the best way to solve the issue? Yes versus `master` — bound is add-tests.

### Evidence
What I checked:
- `go test` pkg/lapi, pkg/appsec, plugin New/ServeHTTP locally passed
- CI: Main Process, e2e (binary + mock LAPI), e2e (docker + pester) all success on run 34042451573 / 34042451595
- PR title `✅ test(plugin): assert LAPI and AppSec report version.go`

### Rank-up moves
None.
