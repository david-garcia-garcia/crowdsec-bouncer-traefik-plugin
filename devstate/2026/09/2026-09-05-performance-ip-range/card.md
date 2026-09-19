Developer review: in progress — 2026-09-05T15:50:59.150Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** Stream and alone Range lookup uses in-process `RangeMembership` (two boolean CIDR sets) on `CrowdsecConnection`. `LookupCachedRemediation` no longer MGETs `range-index`. Redis followers hydrate from the blob on the ticker and at stream start. Spec deltas: `core_plugin_decisions_scopes`, `core_plugin_ip_radix-lookup`.

**End users.** None.

## Motivation
On `origin/master`, stream and alone Range matching MGETs the whole `range-index` blob and tests every CIDR on each request. Allowed traffic (the common miss path) pays O(n) per lookup. Without this change, Range lists in the hundreds to thousands stay in the microsecond-to-sub-millisecond band on every request.

## Merge readiness
Apply is on the branch. Main workflow succeeded on fdc2e4e; E2E was still running on that head. Archive and ready title remain.

Priority: P2 — real operator pain on the allowed-request path, with a workaround of keeping Range lists small
Reviewed head: fdc2e4e
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Apply landed; E2E still in progress on the last measured head |
| CI proof | 3/6 | Main succeeded; E2E in progress |
| Local tests proof | N/A | remote PR; targeted package tests passed |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-performance-ip-range pushed | `git push` origin |
| OpenSpec | in-process-range-membership | `openspec/changes/in-process-range-membership/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/14 | GitHub MCP |
| CI | build 33975795952 success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33975795952 ; E2E 33975795948 in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33975795948 | GitHub Actions API |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | no `comments.md` |
| Security | None. | `devstate/codereview.md` |
| Performance | None. | `devstate/codereview.md` |

## Specs
- [core_plugin_decisions_scopes](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-performance-ip-range/openspec/changes/in-process-range-membership/proposal.md) — modified
- [core_plugin_ip_radix-lookup](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-performance-ip-range/openspec/changes/in-process-range-membership/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
This PR is the Range follow-up that [383](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/383) already named: in-process membership rebuilt from `range-index`. It does not take [368](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/368) (one Redis key per CIDR plus a prefix-length set) or [390](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/390) (batch those candidate keys into one MGET).

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Generation key (`range-index-gen`) or blob-string compare on follower ticks? | assumed — compare the raw `range-index` string to the last hydrated blob; skip a `range-index-gen` key. | explore |
| Where does `LookupCachedRemediation` get the trees? | assumed — add a `*RangeMembership` argument owned by `pkg/decisionscope`. | explore |
| When is the first hydrate relative to serving? | assumed — `startStream` GETs `range-index` and builds membership before returning (no extra LAPI call). | explore |
| How do request-path reads see a rebuild? | assumed — build a new Helper pair from the blob, then store it with `atomic.Value`. | explore |
| What if Redis is unreachable during a follower hydrate? | assumed — keep the last membership; do not replace it with empty. | explore |

## Before merge
- [ ] E2E succeeded on this head [P2]
- [ ] Archive OpenSpec change into `openspec/specs/`
- [ ] Drop WIP title on PR #14
- [x] In-process Range membership applied
- [x] Main workflow succeeded on fdc2e4e

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
| Specs in this PR | 0 added / 2 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | fdc2e4e3ed43895098c9a213f00e2e3c81b609e2 | Card must match the branch you measured |

### Stored data model
None. Redis `range-index` format unchanged.

### Technical review
Best possible solution: Two boolean Helpers on the reclaim value, rebuild from the blob, hydrate followers on the ticker — versus dest’s per-request blob walk, and versus upstream per-CIDR Redis keys.

Related upstream:
- [383](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/383) already landed Range and header-mapped scopes with one `range-index` blob and ban-wins. That card named a local radix rebuilt from the blob as follow-up. This PR is that follow-up. 383 argued to close 368 rather than merge a per-CIDR cache.
- [368](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/368) stores one cache key per Range CIDR plus a grow-only prefix-length set. After review fixes, lookup was still 1+N sequential GETs. The length set can fail the whole feature if Redis evicts it. Out of scope here (no many Redis keys).
- [390](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/390) stacks on 368: one MGET of the candidate keys so a miss is 2 Redis reads instead of 1+N. It keeps most-specific-wins (`10.1.2.3` → captcha `/16`, not ban `/8`). This fork’s spec is ban-wins among all containing CIDRs, so that precedence is the wrong contract.

Do we have a high-confidence way to reproduce? Yes. `pkg/decisionscope` and `connection_range_test.go` cover ban-wins, empty membership ignoring the blob, lease-hit hydrate, and unreachable keep-last.

Is this the best way to solve the issue? Yes versus dest’s blob walk. 368/390 stay on the Redis request path and use longest-prefix precedence; this PR keeps Redis as the shared document and classifies in process with ban-then-captcha.

### Evidence
What I checked:
- `go test ./pkg/decisionscope ./pkg/crowdsecconnection ./pkg/bouncer ./pkg/iplookup` passed
- Main workflow 33975795952 success on fdc2e4e
- E2E 33975795948 in progress on fdc2e4e
- [383](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/383), [368](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/368), [390](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/390)

### Rank-up moves
None.
