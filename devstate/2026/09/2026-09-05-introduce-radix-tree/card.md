Developer review: in progress — 2026-09-05T12:40:25.832Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** OpenSpec change `trusted-ip-radix-lookup` and spec `core_plugin_ip_radix-lookup` are on the branch. Product Checker is still the linear scan until implement. Usage packet `knowledge/devdocs/core_plugin_ip.md` describes the intended Helper/Checker split.

**End users.** None.

## Motivation
Trusted-IP and CIDR membership still walk every entry on each request. Large `ForwardedHeadersTrustedIPs` / `ClientTrustedIPs` lists stay O(n) with no tree in this module. Range remediation is the same linear walk; this ticket does not change that path.

## Merge readiness
Propose is apply-ready; implement has not started. 5 items remain.

Priority: P3 — internal lookup speed; membership results are already correct
Reviewed head: 9d95fa3
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Specs written; no apply yet; CI not seen |
| CI proof | 1/6 | Pushed; checks not seen |
| Local tests proof | N/A | Before implement |
| Review resolution | 6/6 | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-introduce-radix-tree pushed | `git` |
| OpenSpec | trusted-ip-radix-lookup | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/13 | pr-host List |
| CI | not seen | pr-host CI |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | no comments.md |
| Security | None. | no codereview.md |
| Performance | None. | no codereview.md |

## Specs
- [core_plugin_ip_radix-lookup](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-introduce-radix-tree/openspec/changes/trusted-ip-radix-lookup/proposal.md) — added

## Follow-up issues
- [ ] [note] [large] Range remediation still linear (`pkg/decisionscope.MatchRangeFromIndex`) → future radix that can store remediation per CIDR — this ticket forbids Range wiring. Geoblock helper is membership-only.

## How this fits together
Local ticket 2026-09-05-introduce-radix-tree, PR 13 into master, change `trusted-ip-radix-lookup`. Next is implement.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Package path and exported names for the copied helper? | assumed — `pkg/iplookup`, type `Helper`, constructors `NewHelper` / `NewEmptyHelper` | explore |
| How do bare trusted IPs enter a CIDR-only tree? | assumed — format IPv4 as `/32` and IPv6 as `/128` then `AddCIDR` | explore |
| Copy geoblock files verbatim or adapt names/comments to this module? | assumed — adapt names, Apache-2.0 header, cite traefik-geoblock@0c2f46da | explore |
| Which other lookup sites besides Checker? | assumed — none this change; `validateParamsIPs` uses `NewChecker` | explore |

## Before merge
- [ ] Land radix helper in `pkg/ip.Checker` (not Range)
- [x] Stub PR 13 against master
- [x] Requirement written (`qualified-with-gaps`)

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
| Reviewed head | 9d95fa39ee2bdc05b33c66ee40562f6ed1d0cc30 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: In-tree `pkg/iplookup.Helper` wired only into Checker, versus master slice scan.

Do we have a high-confidence way to reproduce? Yes, `ContainsIP` loops in `pkg/ip/ip.go`.

Is this the best way to solve the issue? Yes versus master — copy geoblock bit-walk, no new module, Range left linear.

### Evidence
What I checked:
- `openspec validate trusted-ip-radix-lookup --type change --strict` passed
- `validate-artifact-names.mjs` OK
- FindSpecHost new `core_plugin_ip_radix-lookup`

### Rank-up moves
None.
