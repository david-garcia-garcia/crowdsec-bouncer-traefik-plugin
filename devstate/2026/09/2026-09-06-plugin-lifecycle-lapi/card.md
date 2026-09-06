Developer review: in progress — 2026-09-06T05:29:33Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None.

**End users.** None.

## Motivation
On master, two stream middlewares that share a CrowdSec bouncer key but differ on any reclaim-identity field start two `GET /v1/decisions/stream` pollers against one LAPI cursor. Caches split by `IdentityHex`; bans miss. Matching e2e metrics labels only hides the split. If this does not land, operators keep a silent fail-open stream cache.

## Merge readiness
Not ready for review. Explore is written; waiting on human decisions before propose. Product delta versus `master` is still journal only.

Priority: P1 — stream remediations silently miss on a live LAPI session
Reviewed head: eae03c6
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | CI in progress; no product apply |
| CI proof | 3/6 | in progress (Main Process, e2e mock, e2e pester) |
| Local tests proof | N/A | before implement; remote CI covers proof |
| Review resolution | 6/6 | OPEN PR #23, no review comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-plugin-lifecycle-lapi pushed | `git` origin |
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/23 | pr-host |
| CI | build 34014112201 in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34014112201 | pr-host check runs |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | inventory empty |

## Specs
None.

## Follow-up issues
- [ ] [note] [large] OPEN PR #18 identity `decisionScopeHeaders` splitter → fail-on-conflict on the same LAPI URL+key — different scopes still share one LAPI `stream_cursor`. Isolation already uses `BOUNCER_KEY_TRAEFIK_SCOPES`.

## How this fits together
Local spec on `2026-09-06-plugin-lifecycle-lapi` from `origin/master`, stub PR #23, explore journal written, stopped for human decisions before propose.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Fail `New` on same-session conflicting knobs, or reclaim the first connection and ignore extras? | assumed — fail `New`. Silent ignore is how this bug was born. Share only when the settings snapshot matches. | explore |
| Are different `decisionScopeHeaders` a different stream session or a conflict on one session (URL+key)? | assumed — conflict on one session. LAPI cursor is the bouncer row, not `scopes=`. Do not land PR #18’s two-poller split. | explore |
| Does the session key include LAPI TLS client certificate (keyless TLS bouncer) in addition to `lapiKey`? | assumed — yes. That cert is how LAPI selects the bouncer row when the key is empty. | explore |
| Live/none (and AppSec-only) two usage-metrics tickers on the same bouncer key — fail, share one reporter, or leave as today? | assumed — leave live/none/appsec as today. Stream/alone metrics rides the one session connection. | explore |
| Relationship to OPEN PR #18 (`2026-09-05-scope-headers-identity`)? | assumed — this ticket supersedes putting scopes in the reclaim hash as a splitter. | explore |
| Who owns stream-session identity (cursor / bouncer row)? | assumed — CrowdSec LAPI owns the cursor on the bouncer row. This plugin reuses that: at most one in-process poller per URL+key (and TLS cert). | explore |

## Before merge
- [ ] Make stream session unique in-process (one poller per LAPI URL+key; conflict fails `New`) so two stream middlewares cannot steal one CrowdSec cursor
- [x] Stub PR #23 open from `2026-09-06-plugin-lifecycle-lapi`
- [x] Explore reproduced the two-poller split and wrote `explore.md`

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
| Reviewed head | eae03c6c4d821c4b3b2bce3d1f47c6f6085d414e | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: not merged yet. Explore recommends session = LAPI URL+key (plus TLS cert), fail `New` on conflicting knobs including scopes, reclaim key = session, Redis prefix follows session.

Do we have a high-confidence way to reproduce? Yes — throwaway `New` with metrics 1 vs 600 on one mock LAPI: two connections, `StreamFetches=1/1`, two stream hits.

Is this the best way to solve the issue? Pending human confirm. Putting scopes in the FNV hash (PR #18) would still start two pollers on one CrowdSec cursor.

### Evidence
What I checked:
- Throwaway `go test -run TestRepro_` on dest (deleted, not committed): keys differ for metrics and update interval; scopes not in identity; two pollers on one mock LAPI
- LAPI cursor ownership (`knowledge/research/ext_crowdsec_lapi_stream-cursor/notes.md`)
- `reclaim.Open` binds ctx even on reuse (`pkg/reclaim/table.go`) — conflict check must run before Open
- OPEN PR #18
- CI run 34014112201 in progress

### Rank-up moves
None.
