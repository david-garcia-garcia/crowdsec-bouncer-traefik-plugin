# Explore
IssueKey: 2026-09-05-simpleredis-detach

## Concepts

**Owned SimpleRedis**:
`pkg/simpleredis` is this plugin’s Redis-protocol client (`Init`/`Get`/`Set`/`Del`/`MGet`/`Close`, idle pool, RESP arrays). It is not a git submodule and not a `go.mod` require of `github.com/maxlerebourg/simpleredis`.

**Upstream pin (current, dest `master`)**:
`pkg/simpleredis/SOURCE` plus live spec/usage language that the sources SHALL match simpleredis PR #8 (`pool-redis-connections` @ `f8801cc`). That is the thing this ticket removes.

**Published module ban**:
Runtime still MUST NOT import `github.com/maxlerebourg/simpleredis`. That ban is ownership (use our package), not an upstream pin.

```
  dest master today
  ┌──────────────────────────────────────────────┐
  │ pkg/simpleredis/simpleredis.go  (owned code) │
  │ pkg/simpleredis/LICENSE         (copy stamp) │
  │ pkg/simpleredis/SOURCE          (pin + delta)│
  │ spec: SHALL match outside PR #8              │
  │ usage: "copied from PR #8", Key files SOURCE │
  └──────────────────────────────────────────────┘
                      │ delete LICENSE+SOURCE
                      │ rewrite live spec/usage
                      ▼
  after this change
  ┌──────────────────────────────────────────────┐
  │ pkg/simpleredis/*.go            (this repo)  │
  │ spec: first-party client; no PR #8 match     │
  │ usage: owned client; no SOURCE               │
  └──────────────────────────────────────────────┘
```

Live files that still name an outside source of truth (measured on worktree = `origin/master` plus this bus):

- `pkg/simpleredis/LICENSE`
- `pkg/simpleredis/SOURCE`
- `openspec/specs/core_cache_redis_in-tree-client/spec.md` Purpose + first requirement sentence
- `knowledge/devdocs/core_cache_redis.md` Language + Key files

Not live (history; do not rewrite):

- `openspec/changes/archive/2026-09-05-in-tree-simpleredis-dragonfly-e2e/`
- `openspec/changes/archive/2026-09-05-simpleredis-comms-review/`
- Other tickets’ `devstate/` folders on `master`

`SOURCE`’s Close/timeout delta is already in `simpleredis.go` (`Timeouts are not retried…`) and in the live Close/timeout requirements. Deleting `SOURCE` does not drop that behaviour.

## Decisions

- Fold the spec delta onto existing `core_cache_redis_in-tree-client`. Keep behavioral SHALL (pool pointers, `MGet`, Close, AUTH/SELECT/timeout tests). Drop “copy of PR #8” and “SHALL match PR #8”.
- Delete `LICENSE` and `SOURCE` only under `pkg/simpleredis`. Repo root `LICENSE` stays Apache-2.0.
- Keep the published-module import ban in spec and usage `_Avoid_`.
- Do not change `simpleredis.go` behaviour, comments, or tests for this ticket.
- Do not rewrite archive OpenSpec folders.
- Research `ext_simpleredis_client_pooled-mget/` stays as historical facts about the former origin. Live usage/spec stop treating it as a pin. Index heading/description should stop implying this product still relies on that branch (implement / devdocs-impact).

## Open questions

- Q: Does deleting `pkg/simpleredis/LICENSE` break Apache-2.0 attribution?
  Decision: assumed — no; the file has no named copyright holder (template appendix only), and repo root `LICENSE` is the same Apache-2.0 text. Ticket asked to delete the subdirectory file.
  By: explore

- Q: Should archived OpenSpec changes be rewritten so they no longer mention the copy?
  Decision: assumed — no. Archive is history of how the package entered the tree. Live spec and live usage are the source of truth after detach.
  By: explore

- Q: Should `knowledge/research/ext_simpleredis_client_pooled-mget/` be deleted because there is no upstream?
  Decision: assumed — keep the folder (it records what the outside repo did at a pin). Stop citing it as a live match requirement. Update the domain-index description so it is historical, not “this product relies on”.
  By: explore

- Q: Should the live spec still forbid importing published `github.com/maxlerebourg/simpleredis`?
  Decision: resolved — yes. That is “use our package”, not “track their PR”.
  By: explore

- Q: Who owns client address / Host / trust hop for this change?
  Decision: resolved — none of this ticket’s files set or reconstruct identity. `pkg/ip` / connection identity stay owners elsewhere.
  By: explore
