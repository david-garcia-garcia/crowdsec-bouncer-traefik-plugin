Developer review: in progress — 2026-09-06T15:05:42Z

IssueKey: 2026-09-06-upstream-380-trycap-captcha
JobName: 2026-09-06-upstream-380-trycap-captcha

[sgsi-dev-ticket-status:2026-09-06-upstream-380-trycap-captcha]

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None.

**End users.** None.

## Motivation
On `master`, operators who self-host TryCap Cap Standalone cannot select it as a built-in captcha provider. The plugin only verifies captchas via urlencoded `PostForm`, while Cap Standalone expects JSON `{"secret","response"}` at `/<site_key>/siteverify` with a `cap-token` field — so TryCap fails unless the operator runs an external adapter. Without this change, self-hosted TryCap remains unsupported despite upstream feature request #380.

## Merge readiness
Prepare complete; explore is next. 7 items remain.

Priority: P2 — real operator pain with a workaround (external adapter or misconfigured custom provider).
Reviewed head: 97697a5
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | N/A | Before implement; no product delta yet |
| CI proof | N/A | Stub PR only; no product commits |
| Local tests proof | N/A | Before implement |
| Review resolution | N/A | No PR comments inventoried |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-upstream-380-trycap-captcha pushed | git / GitHub |
| OpenSpec | none | openspec/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/40 | GitHub MCP Create |
| CI | not seen | pr-host CI |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md absent |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local ticket (upstream #380 assessment) → branch `2026-09-06-upstream-380-trycap-captcha` from `origin/master` → stub PR #40 opened in prepare → explore next to resolve template/config unknowns before propose.

## Decision needed
None.

## Before merge
None.

## Findings
None.

## Axis review
None.

## Agent review details

### Stored data model
None.
