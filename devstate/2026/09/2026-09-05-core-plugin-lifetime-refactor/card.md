Developer review: in progress — 2026-09-05T07:01:57.287Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** Explore now uses sister reclaim (`pkg/reclaim` from geoblock/modsecurity) for CrowdsecConnection lifetime instead of `sync.Once`. Still no plugin runtime vs `master`.

**End users.** None.

## Motivation
On `master`, Traefik still constructs one handler per router while stream ticker and cache live as process globals, and `New` discards its context. Traefik cancels that context on reload then calls `New` again within milliseconds. Without reclaim, a split either never disposes tickers or drops the stream on every reload.

## Merge readiness
Explore rewritten around reclaim; waiting on design agreement (especially Connection key vs WAF name+config). Not ready for review. 2 items remain.

Priority: P3 — internal lifetime split and tests; no current operator or end-user harm
Reviewed head: 0c87fad
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | New head just pushed; CI not seen yet. Design still needs a human |
| CI proof | 1/6 | Pushed `0c87fad`; checks not seen on this SHA. Prior head `9d8cd3d` was all success |
| Local tests proof | N/A | Before implement; remote PR |
| Review resolution | 6/6 | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-core-plugin-lifetime-refactor pushed | `git` `0c87fadfb590610e13ddf3bff0e761d62c8cf972` |
| OpenSpec | none | `openspec/changes/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/6 | GitHub PR list |
| CI | not seen on `0c87fad`. Prior `9d8cd3d`: Main Process success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33951191629/job/101266179663 ; e2e (docker + pester) success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33951191618/job/101266212895 ; e2e (binary + mock LAPI) success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33951191618/job/101266212805 | GitHub check runs |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | GitHub PR comments |
| Security | None. | no codereview.md |
| Performance | None. | no codereview.md |

## Specs
None.

## Follow-up issues
- [ ] [take] [small] Empty `TestNew` / stream / query tables in `bouncer_test.go` — replace in this change.
- [ ] [note] [large] `pkg/cache` process-wide `ttl_map` — two Connection keys would still share the memory map.
- [ ] [note] [large] `pkg/logger` never closes `OpenFile`; Windows logging tests fail TempDir cleanup.

## How this fits together
Worktree from `origin/master`. Stub PR #6 is the durable card. Explore stopped for agreement; reclaim is now the Connection lifetime.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Must CreateConfig/New stay in the module-root package? | assumed — yes; thin root to plugin.go | explore |
| How is CrowdsecConnection shared? | resolved — reclaim table (geoblock/modsecurity), not sync.Once | explore |
| Reclaim key = WAF name+full config, or connection-field hash without name? | assumed — crowdsecconnection: + LAPI/redis/stream/AppSec client hash; not middleware name | explore |
| Does captcha live on Connection or Bouncer? | assumed — Bouncer | explore |
| Does AppSec live on Connection or Bouncer? | assumed — Connection owns client+host; Bouncer calls on pass when enabled | explore |
| Type spelling CrowdSecConnection vs CrowdsecConnection? | assumed — CrowdsecConnection / crowdsecconnection | explore |
| How far does exquisite coverage go beyond compiled tests? | assumed — go test reclaim grace/reclaim/dispose + fake LAPI; existing e2e for Yaegi | explore |

## Before merge
- [ ] Agree the reclaim design (especially Connection key vs WAF name+config) before propose
- [ ] CI on head `0c87fad` not seen yet

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
| Reviewed head | 0c87fadfb590610e13ddf3bff0e761d62c8cf972 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Copy `pkg/reclaim`; store CrowdsecConnection as the incarnation; Bouncer is ForRoute. Matches Traefik cancel-then-New and sister WAF/geoblock. `sync.Once` cannot dispose tickers on unload or survive the 1 ms reload gap.

Do we have a high-confidence way to reproduce? Yes — `New(_ context.Context` ignores ctx; sisters `reclaim.Open(ctx, …)` in `traefik-modsecurity/modsecurity.go` and `traefik-geoblock/plugin.go`.

Is this the best way to solve the issue? Yes vs `master`, if the Connection key omits middleware name (otherwise each alias gets its own stream).

### Evidence
What I checked:
- `D:\repositories\traefik-geoblock\pkg\reclaim\table.go` Open/bind/orphan/reclaim/dispose
- `D:\repositories\traefik-modsecurity\modsecurity.go` bindPlugin + `plugin_reuse_test.go`
- `bouncer.go` `New(_ context.Context` discards ctx
- Prior PR #6 CI all success on `9d8cd3d`

### Rank-up moves
None.
