## Motivation
The tree already pins `traefik-middleware-utilities` for reclaim, SimpleRedis, and iplookup. Dest still requires `v1.0.6`. Two APIs the tree already uses are not in that pin: the generation-Apply test helper lives under `pkg/traefikemulator`, and reclaim `SetAlias` / `Watch` / `ClearPublisher` / `Peek` live as a hand-patched vendor tree.

Published `v1.0.7` already ships both. Dest therefore keeps a second owner of the emulator file and an ad-hoc Peek that published `v1.0.6` does not have. Main Process CI comments `go mod vendor` out so a restore of that published tree does not drop Peek and fail typecheck. Live specs still name `v1.0.6` and say Peek is ad-hoc on vendored `table.go`.

If those copies stay, a later vendor restore or a catalog load that does not use this `vendor/` drops Peek, and exclusive-name detection cannot compile. The emulator remains a second owner of a file that already exists at the published tag. Catalog and usage sentences still promise a pin and a vendor override that are no longer the source of those APIs.

Priority: P3 — pin, local copies, and CI vendor skip, no current operator or user harm

## Implementation
Require `traefik-middleware-utilities v1.0.7` and re-vendor so `vendor/` matches the published module: reclaim (alias and Peek) and `traefikemulator`. Do not re-apply the dest reclaim vendor diff. Delete `pkg/traefikemulator` and point the remaining caller at the published import. Swap the Test depguard allowlist and the helper doc to that path. Keep `pkg/reclaim` as the only product import of utilities reclaim.

Re-enable `go mod vendor` and the vendor git-diff on Main Process. Before Yaegi, copy the vendored utilities tree onto `$GOPATH/src` so the test-only `traefikemulator` import resolves (Yaegi v0.16 does not load it from `vendor/`). Fold the live spec pin `v1.0.6` to `v1.0.7` and the Peek-owner sentence onto the published table method.

## What this changes
**Operators.** None.
**Admin users.** None.
**Developers.** Tests import `github.com/david-garcia-garcia/traefik-middleware-utilities/traefikemulator` (the local package is gone); `go.mod` pins utilities `v1.0.7` with published reclaim Peek and alias; callers still use the `pkg/reclaim` shim; Yaegi root-package tests need that module on `$GOPATH/src`.
**End users.** None.

## Merge readiness
Ready for review. 1 items remain.

Priority: P3 — pin, local copies, and CI vendor skip, no current operator or user harm
Reviewed head: 1a44864b
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Ready |
| CI proof | 6/6 | succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35983279559 |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-24-adopt-utilities-v1-0-7 pushed | `git` |
| OpenSpec | adopt-utilities-v1-0-7 | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/147 | pr-host |
| CI | build 35983279559 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35983279559 | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35983279559 |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_decisions_scopes](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-adopt-utilities-v1-0-7/openspec/changes/adopt-utilities-v1-0-7/proposal.md) — modified
- [core_plugin_decisionstore_store](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-adopt-utilities-v1-0-7/openspec/changes/adopt-utilities-v1-0-7/proposal.md) — modified
- [std_go_reclaim_context-lease](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-adopt-utilities-v1-0-7/openspec/changes/adopt-utilities-v1-0-7/proposal.md) — modified

Completed:
- [core_plugin_decisions_scopes](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-adopt-utilities-v1-0-7/openspec/specs/core_plugin_decisions_scopes/spec.md) — modified
- [core_plugin_decisionstore_store](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-adopt-utilities-v1-0-7/openspec/specs/core_plugin_decisionstore_store/spec.md) — modified
- [std_go_reclaim_context-lease](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-adopt-utilities-v1-0-7/openspec/specs/std_go_reclaim_context-lease/spec.md) — modified


## Deviations from the ask
None.

## Follow-up issues
- [ ] [Rename `ext_traefik-middleware-utilities_packages` to a leaf that names the object](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-adopt-utilities-v1-0-7/knowledge/debt/2026-09-24-rename-utilities-packages-research.md) — research slug `packages` hides the object (Name for the scope).


## How this fits together
Ticket 2026-09-24-adopt-utilities-v1-0-7 on branch 2026-09-24-adopt-utilities-v1-0-7 targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/147; CI build 35983279559 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35983279559.

## Explore Decisions
None.

## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-adopt-utilities-v1-0-7/devstate/2026/09/2026-09-24-adopt-utilities-v1-0-7/codereview_standards.md) — 1 total, 0 pending, 0 completed, 1 skipped
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-adopt-utilities-v1-0-7/devstate/2026/09/2026-09-24-adopt-utilities-v1-0-7/codereview_nitpicks.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-adopt-utilities-v1-0-7/devstate/2026/09/2026-09-24-adopt-utilities-v1-0-7/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-adopt-utilities-v1-0-7/devstate/2026/09/2026-09-24-adopt-utilities-v1-0-7/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-adopt-utilities-v1-0-7/devstate/2026/09/2026-09-24-adopt-utilities-v1-0-7/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-adopt-utilities-v1-0-7/devstate/2026/09/2026-09-24-adopt-utilities-v1-0-7/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-adopt-utilities-v1-0-7/devstate/2026/09/2026-09-24-adopt-utilities-v1-0-7/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-adopt-utilities-v1-0-7/devstate/2026/09/2026-09-24-adopt-utilities-v1-0-7/codereview_coverage.md) — 0 total, 0 pending, 0 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 6 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 1a44864b632f69039349fb01f179a65072893991 | Card must match the branch you measured |

### Stored data model
None.
