Developer review: in progress — 2026-09-05T07:48:50.000Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** Apply-ready OpenSpec `crowdsec-connection-bouncer-split`: Yaegi `New` reclaims a `CrowdsecConnection` by connection-field hash (not middleware name); each connection owns an isolated cache; mock e2e will prove two middlewares in one Traefik. Runtime still matches `master` until implement.

**End users.** None.

## Motivation
On `master`, stream ticker, decision cache, and LAPI health are process globals, so a second Crowdsec bouncer config in the same Traefik is first-wins. Operators cannot run two backends or compare configs side-by-side. Without this change that sharing stays the product.

## Merge readiness
Propose is apply-ready; implement has not started. Not ready for review. 2 items remain.

Priority: P2 — operators cannot run two Crowdsec configs in one Traefik; workaround is a second Traefik
Reviewed head: 57b10f6
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Propose landed; CI still running; no product code yet |
| CI proof | 3/6 | Checks queued/in progress on `57b10f6` |
| Local tests proof | N/A | Before implement; remote PR |
| Review resolution | 6/6 | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-core-plugin-lifetime-refactor pushed | `git` `57b10f6f0048365485dc1ab6d3211d5b6fda4f1e` |
| OpenSpec | crowdsec-connection-bouncer-split | `openspec/changes/crowdsec-connection-bouncer-split/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/6 | GitHub PR list |
| CI | Main Process in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33953564976/job/101272681659 ; e2e (binary + mock LAPI) queued https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33953564971/job/101272681682 ; e2e (docker + pester) queued https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33953564971/job/101272681772 | GitHub check runs |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | GitHub PR comments |
| Security | None. | no codereview.md |
| Performance | None. | no codereview.md |

## Specs
- [core_plugin_middleware_instance-reclaim](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-core-plugin-lifetime-refactor/openspec/changes/crowdsec-connection-bouncer-split/proposal.md) — added
- [core_cache_client_isolated-store](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-core-plugin-lifetime-refactor/openspec/changes/crowdsec-connection-bouncer-split/proposal.md) — added
- [std_go_reclaim_context-lease](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-core-plugin-lifetime-refactor/openspec/changes/crowdsec-connection-bouncer-split/proposal.md) — added
- [build_e2e_mock_dual-bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-core-plugin-lifetime-refactor/openspec/changes/crowdsec-connection-bouncer-split/proposal.md) — added

## Follow-up issues
- [ ] [take] [small] Empty `TestNew` / stream / query tables in `bouncer_test.go` — replace in this change.
- [ ] [take] [small] `pkg/cache` process-wide `ttl_map` → per-Connection isolated store.
- [ ] [take] [small] Mock e2e scenario: one Traefik, two bouncer middlewares, two LAPIs.
- [ ] [note] [large] `pkg/logger` never closes `OpenFile`; Windows logging tests fail TempDir cleanup.

## How this fits together
Worktree from `origin/master` (includes in-tree SimpleRedis). Stub PR #6 is the durable card. Propose is apply-ready; next is implement.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Must CreateConfig/New stay in the module-root package? | assumed — yes; thin root to plugin.go | explore |
| Does captcha live on Connection or Bouncer? | assumed — Bouncer | explore |
| Does AppSec live on Connection or Bouncer? | assumed — Connection owns client+host; Bouncer calls on pass when enabled | explore |
| Type spelling CrowdSecConnection vs CrowdsecConnection? | assumed — CrowdsecConnection / crowdsecconnection | explore |

## Before merge
- [ ] Implement the apply-ready change (reclaim copy, isolated cache, two-config tests, dual-bouncer mock e2e)
- [ ] CI on head `57b10f6` still in progress

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
| Specs in this PR | 4 added / 0 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 57b10f6f0048365485dc1ab6d3211d5b6fda4f1e | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Copy `pkg/reclaim`; store CrowdsecConnection as the incarnation keyed by connection fields; Bouncer is ForRoute. Isolated cache (private map + Redis prefix) so two backends cannot share remediations. `sync.Once` cannot dispose tickers or survive Traefik’s reload gap.

Do we have a high-confidence way to reproduce? Yes — `New(_ context.Context` ignores ctx; globals at `bouncer.go` 47–62; sisters `reclaim.Open` in geoblock/modsecurity.

Is this the best way to solve the issue? Yes vs `master`: connection-field key (not middleware name) so same LAPI shares one ticker and two LAPIs stay isolated.

### Evidence
What I checked:
- `openspec validate crowdsec-connection-bouncer-split --strict` valid
- FindSpecHost verdicts on `devstate/.../specs.md`
- GitHub check runs on PR #6 head `57b10f6` (queued / in progress)

### Rank-up moves
None.
