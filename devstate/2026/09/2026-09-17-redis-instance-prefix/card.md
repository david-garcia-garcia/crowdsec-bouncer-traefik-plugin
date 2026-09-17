Developer review: in progress — 2026-09-17T14:32:00Z

## What this changes
**Operators.** Optional Traefik key `redisCacheInstanceId` scopes Redis cache keys per bouncer instance when `redisCacheEnabled` (empty after trim → hostname; set pod name via downward API for stable keys across restarts).

**Admin users.** None.

**Developers.** `lapi.CachePrefix` appends `:{instanceId}` when Redis is on; OpenSpec change archived; live spec `core_cache_client_isolated-store` merged instance-prefix requirements.

**End users.** None.

## Motivation
On `master`, two Traefik pods with the same LAPI key and `redisCacheEnabled` share one Redis namespace keyed only by LAPI session hex. CrowdSec LAPI assigns a separate stream cursor per bouncer row (hashed API key plus outbound client IP), so each pod should poll independently. The shared `updated` lease instead makes one pod skip LAPI while others reuse the same dump and remediation keys — a multi-pod correctness bug, not a reason to remove Redis (PR #59 was dropped for that).

```mermaid
sequenceDiagram
  participant PodA
  participant PodB
  participant Redis
  participant LAPI
  PodA->>Redis: SET updated (lease)
  PodA->>LAPI: stream poll
  PodB->>Redis: GET updated (hit)
  Note over PodB,LAPI: PodB skips LAPI despite distinct LAPI cursor
```

If we do not merge instance-scoped prefixes, operators who centralize Redis for durability still get wrong stream sharing across replicas.

## Merge readiness
OpenSpec archive and catalog sync complete; pullrequest phase remains. 1 workflow item left.

Priority: P2 — multi-pod stream/cache corruption with a workaround (disable Redis or isolate Redis per pod).

Reviewed head: c2027ca
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Archive done; CI not green on latest head yet |
| CI proof | 3/6 | Checks re-running after 38df826; prior mixed conclusions |
| Local tests proof | 6/6 | `go test ./pkg/lapi/ ./pkg/cache/ ./pkg/configuration/` passed |
| Review resolution | N/A | No PR comments inventoried |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-17-redis-instance-prefix pushed | git |
| OpenSpec | redis-instance-prefix archived | `openspec/changes/archive/2026-09-17-redis-instance-prefix/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/60 | handoff.yaml |
| CI | not seen on archive head | PR check runs |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | PR #60 |

## Specs
- [proposal (archive)](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-17-redis-instance-prefix/openspec/changes/archive/2026-09-17-redis-instance-prefix/proposal.md)
- [design (archive)](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-17-redis-instance-prefix/openspec/changes/archive/2026-09-17-redis-instance-prefix/design.md)
- [tasks (archive)](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-17-redis-instance-prefix/openspec/changes/archive/2026-09-17-redis-instance-prefix/tasks.md)
- [core_cache_client_isolated-store](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-17-redis-instance-prefix/openspec/specs/core_cache_client_isolated-store/spec.md)

## Follow-up issues
None.

## How this fits together
Local ticket → branch `2026-09-17-redis-instance-prefix` → stub PR #60 → explore → propose → implement → codereview → devdocs impact → archive (closed) → pullrequest.

## Decision needed
None.

## Before merge
- [x] [P2] Explore instance identity (hostname vs config knob) and warn-and-wire interaction
- [x] [P2] Propose OpenSpec + devdocs (Redis as per-instance store, not stream bus)
- [x] [P2] Implement `CachePrefix` instance dimension; keep `redisCacheEnabled`
- [x] [P2] Six-axis code review (hostname-fail test added)
- [x] [P3] Devdocs impact: isolated cache + redis Language/usage
- [x] [P2] Archive OpenSpec delta into `core_cache_client_isolated-store`
- [x] Prepare: requirement, worktree, stub PR

## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-17-redis-instance-prefix/devstate/2026/09/2026-09-17-redis-instance-prefix/codereview_standards.md) — 1 total, 0 pending, 0 completed, 1 skipped
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-17-redis-instance-prefix/devstate/2026/09/2026-09-17-redis-instance-prefix/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-17-redis-instance-prefix/devstate/2026/09/2026-09-17-redis-instance-prefix/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-17-redis-instance-prefix/devstate/2026/09/2026-09-17-redis-instance-prefix/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-17-redis-instance-prefix/devstate/2026/09/2026-09-17-redis-instance-prefix/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-17-redis-instance-prefix/devstate/2026/09/2026-09-17-redis-instance-prefix/codereview_coverage.md) — 1 total, 0 pending, 1 completed

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| OpenSpec archive | `2026-09-17-redis-instance-prefix` | change folder moved; catalog validators OK |
| Spec fold | `core_cache_client_isolated-store` | delta synced to live spec |
| Devdocs impact findings | 3 produced, 0 open | prior phase |

### Stored data model
| Store | Field | Type | Sample |
| --- | --- | --- | --- |
| Traefik plugin config | redisCacheInstanceId | string (optional) | `my-pod-7` |
| Redis key prefix | CachePrefix | string | `{sessionHex}:{instanceId}` when Redis enabled |

### Technical review
Instance isolation is prefix-only; reclaim and LAPI row selection unchanged. Hostname fallback uses `unknown-instance` with one Warn when `os.Hostname()` fails (unit-tested via `readProcessHostname` seam).

Do we have a high-confidence way to reproduce? Partial — unit tests for prefix shape, lease key separation, and hostname-fail fallback; live multi-pod Redis not run this phase.

[sgsi-dev-ticket-status:2026-09-17-redis-instance-prefix]
