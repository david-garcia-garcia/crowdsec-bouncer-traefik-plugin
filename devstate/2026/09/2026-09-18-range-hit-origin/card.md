Developer review: in progress — 2026-09-18T17:59:26Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None.

**End users.** None.

## Motivation
On DestBranch, stream mode with the in-memory DecisionStore already knows the winning Range prefix from the radix walk. It then re-parses every stored CIDR to recover the letter and optional origin of that prefix. A miss skips that walk; a hit does not.

That second scan is the request-path cost: ticket-measured compiled Go is about 40µs and 2k allocs at 1k CIDRs, and about 450µs and 20k allocs at 10k. A miss is already tens of nanoseconds and zero allocs. Not merging leaves every Range ban or captcha paying that linear parse on the hot path.

```mermaid
flowchart TD
  req[Client IP on stream in-memory path] --> radix[Radix IsContained]
  radix -->|miss| empty[Empty remediation]
  radix -->|hit plus prefixLen| walk[ParseCIDR every stored CIDR]
  walk --> stored[Letter and origin of matching prefix]
```

## Merge readiness
Prepare is grounded and the stub PR is open. Product apply has not started. 1 item remains.

Priority: P2 — request-path latency on every Range hit, limited to stream plus in-memory
Reviewed head: 67fbb9e
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Stub PR is open; required CI is still running |
| CI proof | 3/6 | Checks in progress on the stub head |
| Local tests proof | N/A | Before implement; remote CI is the proof axis |
| Review resolution | 6/6 | No open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-18-range-hit-origin pushed | `git` origin/2026-09-18-range-hit-origin |
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/106 | pr-host Create |
| CI | build 35377363596 in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35377363596 | pr-host CI |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | no comments.md; inventory empty |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local ticket 2026-09-18-range-hit-origin is on branch 2026-09-18-range-hit-origin and stub PR 106. CI is running on the stub head; explore has not started.

## Decision needed
None.

## Before merge
- [ ] Put the stored Range letter and optional origin on the radix endpoint so a stream in-memory hit is O(prefix)

## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | Same list as ## Specs; do not paste diff --stat |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 67fbb9e36c17bcf818bfc2977afa46009ee3cf64 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: DestBranch still recovers origin by walking every stored CIDR after the radix already has the winning prefix.

Do we have a high-confidence way to reproduce? Yes, `RangeMembership.Remediation` after `IsContained` calls `storedMatchingPrefix`, which `ParseCIDR`s `storedByCIDR`.

Is this the best way to solve the issue? Yes for this ticket — store the letter and origin on the endpoint the walk already stops on; keep two trees so ban still wins.

### Evidence
What I checked:
- Named files exist on origin/master (`git ls-tree`, 46a81d0)
- `storedMatchingPrefix` walks `storedByCIDR` (`pkg/decisionscope/rangemembership.go`)
- `radixNode` has no remediation payload (`pkg/iplookup/iplookup.go`)
- One OPEN PR 106; comment inventory empty
- Product delta `origin/master...HEAD` excluding `devstate/` is empty

### Rank-up moves
None.
