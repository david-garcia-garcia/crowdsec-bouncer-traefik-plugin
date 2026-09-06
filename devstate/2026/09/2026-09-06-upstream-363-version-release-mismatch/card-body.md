Developer review: in progress — 2026-09-06T15:12:02Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None versus `master`. Explore recorded test seams for LAPI usage-metrics `version`, LAPI/AppSec User-Agent, and `version.go` wiring; product tests are not landed yet.

**End users.** None.

## Motivation
On `master`, `cscli bouncers list` can show a stale plugin version if a tag ships while `version.go` still names the previous release (upstream #322 and #363). This fork already bumps `version.go` before tagging, and the tree currently reports `v1.7.1`, but no test asserts usage-metrics `remediation_components[].version` or `User-Agent: Crowdsec-Bouncer-Traefik-Plugin/<version>`. Without those tests, a future manual release bypass can regress undetected.

## Merge readiness
Explore complete; propose next. Product tests not yet in the diff.

Priority: P3 — spec, docs, tests, or internal clarity — no current user or operator harm
Reviewed head: 79a94a0
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | CI still running; no product tests landed |
| CI proof | 3/6 | Checks in progress on [run 34041478270](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041478270) |
| Local tests proof | N/A | Before implement; remote PR uses CI proof |
| Review resolution | 6/6 | No open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-upstream-363-version-release-mismatch pushed | git push 79a94a0 |
| OpenSpec | none | handoff.yaml change: none |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/53 | GitHub #53 |
| CI | build 34041478270 in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041478270 | pull_request_read get_check_runs |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | comments: none |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local add-tests ticket for upstream #322+#363 → explore chose httptest seams (LAPI JSON+User-Agent, AppSec User-Agent, root `New` wiring) → stub PR #53 → propose will write the OpenSpec change.

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
| Specs in this PR | none | No spec.md versus `master` |
| Open reviewer comments walked | 0 | No PR comments |
| Reviewed head | 79a94a080ef52a348f8e6e70502a26cb40f7b293 | Card matches latest push |

### Stored data model
None.

### Technical review
Best possible solution: add-tests on existing httptest harnesses, no product behavior change versus `master`.

Do we have a high-confidence way to reproduce? No for the runtime stale-tag symptom (`version.go` already reads `v1.7.1`). Yes for the test gap: metrics tests inject `"test"` and never assert `version` or User-Agent.

Is this the best way to solve the issue? Yes versus `master` — bound is add-tests; release workflows already own tagging.

### Evidence
What I checked:
- `version.go`, `plugin.go`, `pkg/lapi/client_metrics.go`, `pkg/lapi/client_http.go`, `pkg/appsec/query.go`, `pkg/appsec/test_client.go`
- `pkg/lapi/metrics_test.go`, `plugin_test.go` (no User-Agent capture)
- `openspec/specs/core_plugin_lapi_usage-metrics/spec.md` Envelope identity
- `knowledge/research/ext_crowdsec_lapi_usage-metrics/notes.md` (User-Agent stamps bouncer row version)
- CI check_runs on PR #53 (79a94a0)

### Rank-up moves
None.
