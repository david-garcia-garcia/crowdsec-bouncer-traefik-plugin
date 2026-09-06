Developer review: in progress — 2026-09-06T15:22:15Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** Tests assert LAPI usage-metrics `remediation_components[].version` and LAPI/AppSec `User-Agent` carry the constructed plugin version, and that `New` uses `version.go` `pluginVersion`. Runtime reporting is unchanged versus `master`.

**End users.** None.

## Motivation
On `master`, `cscli bouncers list` can show a stale plugin version if a tag ships while `version.go` still names the previous release (upstream #322 and #363). This fork already bumps `version.go` before tagging, and the tree currently reports `v1.7.1`, but no test asserted usage-metrics `version` or User-Agent. Without those tests, a future manual release bypass can regress undetected.

## Merge readiness
Implement landed httptests; CI on this head is still queued.

Priority: P3 — spec, docs, tests, or internal clarity — no current user or operator harm
Reviewed head: a5ec681
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | CI queued after implement push |
| CI proof | 3/6 | Checks queued on [run 34042084304](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34042084304) |
| Local tests proof | N/A | Remote PR uses CI proof |
| Review resolution | 6/6 | No open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-upstream-363-version-release-mismatch pushed | git push a5ec681 |
| OpenSpec | assert-plugin-version-reporting | openspec/changes/assert-plugin-version-reporting |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/53 | GitHub #53 |
| CI | build 34042084304 queued https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34042084304 | pull_request_read get_check_runs |
| Local tests | passed | `go test` pkg/lapi, pkg/appsec, and plugin New/ServeHTTP tests |
| PR comments | no comments | comments: none |

## Specs
- [core_plugin_lapi_usage-metrics](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-363-version-release-mismatch/openspec/changes/assert-plugin-version-reporting/proposal.md) — modified
- [core_plugin_appsec_client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-363-version-release-mismatch/openspec/changes/assert-plugin-version-reporting/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
Local add-tests ticket for upstream #322+#363 → httptests on PR #53 → CI queued on a5ec681.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Which seam proves `version.go` is what LAPI/cscli would record, without exporting `pluginVersion`? | assumed — pkg/lapi httptest with an injected distinctive version proves the Client copies version into JSON and User-Agent; a root-package `New` test asserts that User-Agent uses the unexported `pluginVersion` from `version.go`. AppSec Query httptest covers the sibling User-Agent. Do not export the var. | explore |
| Does a static `version.go` vs git-tag or workflow-YAML test add value? | assumed — no. Unit tests have no release tag. `release-publish.yml` already exits 1 when commit message and `version.go` disagree. Bound is add-tests, not workflow edits. | explore |
| Should `NewTestClient` grow a version argument? | assumed — set `pluginVersion` on the Client in the new AppSec test. Change `NewTestClient` only if the field cannot be set from `query_test.go` (same package: it can). | explore |

## Before merge
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
| Reviewed head | a5ec681fe37a521aedd29a4cc79aeaba11244c43 | Card matches latest push |

### Stored data model
None.

### Technical review
Best possible solution: httptest on existing Client and `New` seams; no runtime change versus `master`.

Do we have a high-confidence way to reproduce? Yes for the test gap — `TestReportMetricsPluginVersion`, `Test_appsecQuery_userAgentIncludesPluginVersion`, and `TestNew_LAPIUserAgentUsesVersionGo` passed locally.

Is this the best way to solve the issue? Yes versus `master` — bound is add-tests.

### Evidence
What I checked:
- `go test ./pkg/lapi` and `./pkg/appsec` passed
- `go test . -run TestNew_|TestServeHTTP|TestBouncer_ServeHTTP` passed (30.3s)
- Root `go test .` also hit Windows TempDir file-lock on `TestBouncerFileLogging*` (pre-existing log handle, not these tests)
- CI check_runs queued on PR #53 after a5ec681

### Rank-up moves
None.
