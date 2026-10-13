Developer review: in progress — 2026-09-17T06:24:30Z

[sgsi-dev-ticket-status:2026-09-17-upstream-reclaim-simpleredis]

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** Prepare only: requirement and research on swapping in-tree `pkg/reclaim` and `pkg/simpleredis` for traefik-middleware-utilities; no product swap yet.

**End users.** None.

## Motivation
The plugin keeps local copies of reclaim and simpleredis under `pkg/` on `master` while the same author maintains canonical packages in traefik-middleware-utilities. That fork drift makes bugfixes and Yaegi hardening land twice and lets the in-tree reclaim API (value Sleep/Wake/Close) diverge from upstream Hooks-based Open.

If we never realign, session reuse and Redis pooling fixes in the utilities repo will not reach this plugin without manual merges, and the live spec that forbids tracking an outside simpleredis repo will keep blocking an intentional upstream sync.

Priority: P3 — internal alignment and spec tension; no current operator or end-user failure on `master`.

## Merge readiness
Prepare complete (`qualified-with-gaps`); explore is next. 0 PR comment items remain.

Priority: P3 — internal alignment and spec tension; no current operator or end-user failure on `master`.
Reviewed head: 8f2dd28
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | N/A | Before implement |
| CI proof | 1 | Pushed; checks not measured yet |
| Local tests proof | N/A | Before implement |
| Review resolution | N/A | No PR comments to walk |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-17-upstream-reclaim-simpleredis pushed | origin |
| OpenSpec | none | handoff.yaml |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/56 | GitHub |
| CI | not seen | not measured |
| Local tests | none | handoff.yaml |
| PR comments | no comments | empty set |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local ticket → branch `2026-09-17-upstream-reclaim-simpleredis` from `master` → stub PR #56 → CI pending measurement.

## Decision needed
None.

## Before merge
None.

## Findings
None.

## Axis review
None.

### Stored data model
None.
