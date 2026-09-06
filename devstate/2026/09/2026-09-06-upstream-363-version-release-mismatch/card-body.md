Developer review: in progress — 2026-09-06T15:06:47Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** Prepare bus only: requirement grounded on `version.go`, LAPI metrics User-Agent paths, and release workflows; tests for version reporting not yet landed.

**End users.** None.

## Motivation
On `master`, upstream #322/#363 showed `cscli bouncers list` reporting a stale plugin version when releases were tagged without bumping `version.go` first (Traefik caches the tagged archive). This fork mitigates via release-prepare/publish workflows, and `version.go` currently reads `v1.7.1`, but no unit test asserts usage-metrics `remediation_components[].version` or LAPI/AppSec User-Agent headers carry the configured version. Without tests, a future manual release bypass could regress the same failure mode undetected.

## Merge readiness
Prepare complete; explore next. 7 workflow phases remain.

Priority: P3 — spec/tests/internal clarity; no current operator harm on master.
Reviewed head: 0d9b527
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | N/A | Prepare only; no product delta yet |
| CI proof | N/A | Before first product push beyond bus |
| Local tests proof | N/A | Before implement |
| Review resolution | 6/6 | No open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-upstream-363-version-release-mismatch pushed | git push 0d9b527 |
| OpenSpec | none | handoff.yaml change: none |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/53 | GitHub #53 |
| CI | not seen | no checks measured yet |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | comments: none |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local bug-hunt assessment (upstream #322 + #363, add-tests) → prepare bus on dedicated worktree → stub PR #53 → explore will pick test seams.

## Decision needed
None.

## Before merge
- [x] Prepare: dump, requirement, qualify, worktree, stub PR
- [ ] Explore test seams for version reporting paths
- [ ] Implement version assertion tests (LAPI metrics + User-Agent)
- [ ] CI green on product commits

## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | Prepare only |
| Open reviewer comments walked | 0 | No PR comments |
| Reviewed head | 0d9b527 | Latest push |

### Stored data model
None.

### Technical review
Best possible solution: not evaluated yet — prepare grounded paths only.

Do we have a high-confidence way to reproduce? No — tests not written; explore will confirm httptest seams.

Is this the best way to solve the issue? TBD at implement — bound is add-tests, not behavior change.

### Evidence
What I checked:
- `version.go`, `plugin.go`, `pkg/lapi/client_metrics.go`, `pkg/lapi/client_http.go`, `pkg/appsec/query.go`
- `.github/workflows/release-prepare.yml`, `.github/workflows/release-publish.yml`
- `pkg/lapi/metrics_test.go` (no version field assertion)

### Rank-up moves
None.
