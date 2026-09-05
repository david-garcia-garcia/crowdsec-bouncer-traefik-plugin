Developer review: ready for review — 2026-09-05T13:11:33.417Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** `pkg/ip.Checker` stores trusted CIDRs in in-tree `pkg/iplookup.Helper` (radix membership). Public Checker API and Traefik keys are unchanged. Range matching is still the linear `range-index` walk. Spec `core_plugin_ip_radix-lookup` is in the catalog.

**End users.** None.

## Motivation
On master, trusted-IP and CIDR membership walked every configured network on each request. Large `ForwardedHeadersTrustedIPs` / `ClientTrustedIPs` lists stayed O(n). Without this PR that linear scan remains.

## Merge readiness
Ready for review. 0 items remain.

Priority: P3 — internal lookup speed; membership results are already correct
Reviewed head: 215b2f4
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | CI succeeded; no open comments |
| CI proof | 6/6 | Main, mock e2e, and Pester succeeded |
| Local tests proof | N/A | Remote CI covers this |
| Review resolution | 6/6 | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-introduce-radix-tree pushed | `git` |
| OpenSpec | trusted-ip-radix-lookup (archived) | `openspec/changes/archive/2026-09-05-trusted-ip-radix-lookup/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/13 | pr-host List |
| CI | Main Process success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33968045195/job/101311531739 ; e2e (binary + mock LAPI) success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33968045269/job/101311532332 ; e2e (docker + pester) success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33968045269/job/101311532218 | pr-host CI |
| Local tests | passed | `go test ./pkg/iplookup/ ./pkg/ip/` |
| PR comments | no comments | no comments.md |
| Security | None. | devstate/codereview.md |
| Performance | None. | devstate/codereview.md |

## Specs
- [core_plugin_ip_radix-lookup](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-introduce-radix-tree/openspec/changes/archive/2026-09-05-trusted-ip-radix-lookup/proposal.md) — added

## Follow-up issues
- [ ] [note] [large] Range remediation still linear (`pkg/decisionscope.MatchRangeFromIndex`) → future radix that can store remediation per CIDR — this ticket forbids Range wiring. Geoblock helper is membership-only.

## How this fits together
Local ticket 2026-09-05-introduce-radix-tree, PR 13 into master. Apply is `pkg/iplookup` plus `pkg/ip.Checker`. Range is unchanged on purpose.

## Decision needed
None.

## Before merge
None.

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
| Specs in this PR | 1 added / 0 modified | Same list as Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 215b2f4967f568c31205ab3d7fa2bca0f2e503af | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: In-tree `pkg/iplookup.Helper` wired only into Checker, versus master slice scan.

Do we have a high-confidence way to reproduce? Yes, Checker tests plus CI Main/yaegi and both e2e jobs on 215b2f4.

Is this the best way to solve the issue? Yes versus master — copy geoblock bit-walk, no new module, Range left linear.

### Evidence
What I checked:
- `go test ./pkg/iplookup/ ./pkg/ip/` passed
- Main Process, mock e2e, Pester succeeded on 215b2f4
- Four-axis review: none
- Usage packet `knowledge/devdocs/core_plugin_ip.md` matches the apply

### Rank-up moves
None.
