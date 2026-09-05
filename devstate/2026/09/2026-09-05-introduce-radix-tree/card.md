Developer review: in progress — 2026-09-05T12:36:59.102Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** Research packet `knowledge/research/ext_traefik-geoblock_iplookup/` records the traefik-geoblock radix helper this change will copy. `pkg/ip.Checker` is still the linear CIDR scan. Explore decided: in-tree `pkg/iplookup.Helper`, Checker only, Range unchanged.

**End users.** None.

## Motivation
Trusted-IP and CIDR membership still walk every entry on each request. Large `ForwardedHeadersTrustedIPs` / `ClientTrustedIPs` lists stay O(n) with no tree in this module. Range remediation is the same linear walk; this ticket does not change that path.

## Merge readiness
Explore written; propose has not started. 6 items remain.

Priority: P3 — internal lookup speed; membership results are already correct
Reviewed head: e889397
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Stub PR open; no apply yet; CI not seen |
| CI proof | 1/6 | Pushed; checks not seen |
| Local tests proof | N/A | Before implement |
| Review resolution | 6/6 | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-introduce-radix-tree pushed | `git` |
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/13 | pr-host List |
| CI | not seen | pr-host CI |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | no comments.md |
| Security | None. | no codereview.md |
| Performance | None. | no codereview.md |

## Specs
None.

## Follow-up issues
- [ ] [note] [large] Range remediation still linear (`pkg/decisionscope.MatchRangeFromIndex`) → future radix that can store remediation per CIDR — this ticket forbids Range wiring. Geoblock helper is membership-only.

## How this fits together
Local ticket 2026-09-05-introduce-radix-tree, branch of the same name, stub PR 13 into master. Explore is written; next is propose.

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
| Specs in this PR | none | Same list as Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | e8893973e0bd3c437098df3e0e08bc3d333f63ff | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Copy geoblock bit-walk into `pkg/iplookup` and point Checker at it, versus master still scanning slices.

Do we have a high-confidence way to reproduce? Yes, `go test ./pkg/ip/` passed; Checker has no tests and `ContainsIP` is two loops.

Is this the best way to solve the issue? Yes versus master — in-tree helper, no new module, Range left linear as required.

### Evidence
What I checked:
- `go test ./pkg/ip/ -count=1` passed
- `openspec list --json` empty active changes
- Research notes `ext_traefik-geoblock_iplookup`
- `core_plugin_decisionscope.md` Avoid radix for Range index

### Rank-up moves
None.
