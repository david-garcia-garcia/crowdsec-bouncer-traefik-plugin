## Motivation


## Implementation
Not yet.

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None.

**End users.** None.

## Merge readiness
in progress

Priority: unset
Reviewed head: 6b1015e0e918045f6cc7583dabfd852d399244fd
Owner decision: unset

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Prepare | qualified-with-gaps | The missing header is grounded in pkg/appsec/query.go. The official AppSec encoding is still an unknown. |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Local tests | not seen | Prepare does not run the suite. |
| CI | not seen | Not measured this phase. |

## Specs
None.

## Deviations from the ask
None.

## Follow-up issues
None.

## How this fits together
This fork's AppSec client does not send the client HTTP version. Upstream report: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/400. OpenDev MCP is absent, so the run bus and checkpoints are written by hand. The GitHub update form is broken; the PR summary on https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/189 was not updated. The card in this file is the record.

## Explore Decisions
None.

## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Qualify | qualified-with-gaps | Docs confirmation is still open. |
| PR | #189 | Stub exists. Summary not rewritten. |

### Stored data model
None.
