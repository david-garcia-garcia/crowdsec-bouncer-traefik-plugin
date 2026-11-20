## Motivation
Not yet.

## Implementation
Not yet.

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None.

**End users.** None.

## Merge readiness
In progress. 1 items remain.

Priority: unknown — motivation not written
Reviewed head: b87329d9
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Not ready |
| CI proof | 1/6 | not seen |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-11-20-add-redis-rate-limit-leg pushed | `git` |
| OpenSpec | add-redis-rate-limit-leg | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/228 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [build_e2e_pester_crowdsec-stack](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/openspec/changes/add-redis-rate-limit-leg/proposal.md) — modified
- [core_plugin_lapi_usage-metrics](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/openspec/changes/add-redis-rate-limit-leg/proposal.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/openspec/changes/add-redis-rate-limit-leg/proposal.md) — modified
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/openspec/changes/add-redis-rate-limit-leg/proposal.md) — modified
- [core_plugin_ratelimit_buckets](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/openspec/changes/add-redis-rate-limit-leg/proposal.md) — added
- [core_plugin_ratelimit_client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/openspec/changes/add-redis-rate-limit-leg/proposal.md) — added


## Deviations from the ask
- taken: each bucket carries `match: {method, path, host, headers, cookies}`. → the same `httprule.Rule` predicates are squashed onto the bucket row (`name`, `path`, `host`, …, `key`, `requests`, `window`, `action`), exactly as a `bouncerActionRules` row carries them. `match` and `key` stay separate concepts; only the nesting goes. — `pkg/httprule/action.go (ActionRule embeds Rule with mapstructure:",squash")` — one authoring shape for "which requests" across the plugin, and one less nesting level in Traefik plugin config, where only list → object → list depth is proven by the existing e2e.. Requester: not asked.


## Follow-up issues
- [ ] [Extract a common leg abstraction from `plugin.go` and `Bouncer`](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/knowledge/debt/2026-11-20-extract-common-leg-abstraction.md) — each published leg is copied by hand into five places in `plugin.go` and `Bouncer`; the owner asked to suggest a shared leg unit before the next leg, and the Open-only rate-limit leg does not need it.


## How this fits together
Ticket 2026-11-20-add-redis-rate-limit-leg on branch 2026-11-20-add-redis-rate-limit-leg targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/228; CI not seen.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Does the existing `bypass` action also skip the rate limit? | additive asked — new `bypassRateLimit` token and `SkipRateLimit` field in `pkg/httprule/action.go`; requirement semantics 5 and open decision 1 | assumed — no. Only `bypassRateLimit` skips the rate limit; `bypass` keeps meaning "skip LAPI and AppSec". The `Fold` skip guard change has 1 caller (`pkg/bouncer/bouncer.go:196`). | explore |


## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 2 added / 4 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | b87329d96ab0fb368024415da28128e7b21f2691 | Card must match the branch you measured |

### Stored data model
None.
