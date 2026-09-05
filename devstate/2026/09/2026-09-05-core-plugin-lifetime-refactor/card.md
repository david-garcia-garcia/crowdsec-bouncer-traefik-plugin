Developer review: in progress — 2026-09-05T06:53:07.300Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** Dated ticket bus under `devstate/2026/09/2026-09-05-core-plugin-lifetime-refactor/` and stub PR #6 from `origin/master`. No plugin behavior vs `master`.

**End users.** None.

## Motivation
On `master`, Traefik still constructs one `Bouncer` per route while stream ticker, decision cache, and LAPI health live as process globals inside that same type. `TestNew` is an empty table. Without this change the connection vs request split stays implicit and untested.

## Merge readiness
Prepare grounded; explore is next. Not ready for review. 2 items remain.

Priority: P3 — internal lifetime split and tests; no current operator or end-user harm
Reviewed head: 99fb8b1
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | CI still in progress on the stub PR |
| CI proof | 3/6 | Checks running, not finished |
| Local tests proof | N/A | Before implement; remote PR |
| Review resolution | 6/6 | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-core-plugin-lifetime-refactor pushed | `git` `99fb8b11e567b4d6d25e242b333373f2e078713e` |
| OpenSpec | none | `openspec/changes/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/6 | GitHub PR list |
| CI | build 33950963966 Main Process in_progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33950963966/job/101265514817 ; build 33950963929 e2e (docker + pester) in_progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33950963929/job/101265544578 ; build 33950963929 e2e (binary + mock LAPI) in_progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33950963929/job/101265544523 | GitHub check runs |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | GitHub PR comments |
| Security | None. | no codereview.md |
| Performance | None. | no codereview.md |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local spec dumped on a worktree from freshly fetched `origin/master`. Stub PR #6 is the durable card. This run stops after explore so the CrowdSecConnection vs Bouncer design can be agreed.

## Decision needed
None.

## Before merge
- [ ] Agree the CrowdSecConnection vs Bouncer split in explore before propose
- [ ] Wait for CI on PR #6 (still in progress)

## Findings
None.

## Agent review details

### Security
None.

### Performance
None.

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | No spec.md vs master |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 99fb8b11e567b4d6d25e242b333373f2e078713e | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Not applied yet; prepare only grounded the split (plugin package, CrowdSecConnection, Bouncer) against `bouncer.go` globals.

Do we have a high-confidence way to reproduce? Yes, the first-wins stream ticker and empty `TestNew` are in `bouncer.go` and `bouncer_test.go` on `master`.

Is this the best way to solve the issue? Not chosen yet; explore will propose the package layout.

### Evidence
What I checked:
- Worktree from `origin/master` `4b8d7b25ba7958806c21e30c5888f35dcebbeeb0` (`git fetch` + `git worktree add`)
- `CreateConfig`/`New` and globals in `bouncer.go` (lines 47–73, 75–128, 302–326)
- Process cache singleton in `pkg/cache/cache.go` line 31
- `TestNew` empty table in `bouncer_test.go` lines 43–70
- PR #6 check runs in_progress (GitHub `get_check_runs`)

### Rank-up moves
None.
