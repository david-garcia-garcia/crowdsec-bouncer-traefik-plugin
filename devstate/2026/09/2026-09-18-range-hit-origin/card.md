Developer review: ready for review — 2026-09-18T18:26:53Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** A Range helper endpoint now holds the stored letter and optional origin so a stream in-memory hit is O(prefix). Trusted-IP Checker stays a boolean set.

**End users.** None.

## Motivation
On DestBranch, stream mode with the in-memory DecisionStore already knows the winning Range prefix from the radix walk. It then re-parses every stored CIDR to recover the letter and optional origin of that prefix. A miss skips that walk; a hit does not.

That second scan is the request-path cost. Reproduced here (compiled Go, 1k CIDRs): a hit is about 53µs and 2012 allocs; a miss is 26 ns and zero allocs. Not merging leaves every Range ban or captcha paying that linear parse on the hot path.

```mermaid
flowchart TD
  req[Client IP on stream in-memory path] --> radix[Radix IsContained]
  radix -->|miss| empty[Empty remediation]
  radix -->|hit plus prefixLen| walk[ParseCIDR every stored CIDR]
  walk --> stored[Letter and origin of matching prefix]
```

## Merge readiness
Required CI succeeded. Ready for review. 0 items remain.

Priority: P2 — request-path latency on every Range hit, limited to stream plus in-memory
Reviewed head: c5ae1419
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | OPEN PR, CI succeeded, no open comments |
| CI proof | 6/6 | Main and E2E succeeded on c5ae1419 |
| Local tests proof | N/A | Remote CI is the proof axis; localTests passed |
| Review resolution | 6/6 | No open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-18-range-hit-origin pushed | `git` origin/2026-09-18-range-hit-origin |
| OpenSpec | store-range-remediation-on-radix | `openspec/changes/archive/2026-09-18-store-range-remediation-on-radix/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/106 | pr-host List |
| CI | build 35379782709 success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35379782709 | GitHub Actions API |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | no comments.md; inventory empty |

## Specs
- [core_plugin_ip_radix-lookup](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-18-range-hit-origin/openspec/changes/archive/2026-09-18-store-range-remediation-on-radix/proposal.md) — modified
- [core_plugin_decisions_scopes](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-18-range-hit-origin/openspec/changes/archive/2026-09-18-store-range-remediation-on-radix/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
Local ticket 2026-09-18-range-hit-origin is on branch 2026-09-18-range-hit-origin and OPEN PR 106. Main and E2E succeeded on c5ae1419.

## Decision needed
None.

## Before merge
None.

## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-18-range-hit-origin/devstate/2026/09/2026-09-18-range-hit-origin/codereview_standards.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-18-range-hit-origin/devstate/2026/09/2026-09-18-range-hit-origin/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-18-range-hit-origin/devstate/2026/09/2026-09-18-range-hit-origin/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-18-range-hit-origin/devstate/2026/09/2026-09-18-range-hit-origin/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-18-range-hit-origin/devstate/2026/09/2026-09-18-range-hit-origin/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-18-range-hit-origin/devstate/2026/09/2026-09-18-range-hit-origin/codereview_coverage.md) — 0 total, 0 pending, 0 completed

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 2 modified | Same list as ## Specs; do not paste diff --stat |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | c5ae1419508af5aa313031bd0f7fedbe9d7614d6 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution versus DestBranch: store the blob line on the radix endpoint and drop the request-path ParseCIDR walk.

Do we have a high-confidence way to reproduce? Yes, DestBranch 1k-CIDR hit 52797 ns/op 2012 allocs/op; after apply, Main and E2E succeeded.

Is this the best way to solve the issue? Yes — two helpers, payload on the winning endpoint.

### Evidence
What I checked:
- Main 35379782709 success on c5ae1419
- E2E 35379782783 success on c5ae1419
- One OPEN PR 106; title ⚡️ perf(decisionscope): store Range remediation on the radix endpoint

### Rank-up moves
None.
