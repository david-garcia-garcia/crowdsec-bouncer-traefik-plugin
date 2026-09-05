## Context

See `proposal.md` Why. Dest `master` already runs `pkg/simpleredis` as the Redis client. Live spec Purpose and the first requirement still say the sources SHALL match simpleredis PR #8. `pkg/simpleredis/LICENSE` and `SOURCE` still name that pin. Close/timeout behaviour is already specified and commented in `simpleredis.go`.

FindSpecHost: fold into `core_cache_redis_in-tree-client` (small adjustment to an existing leaf; candidates: `core_cache_redis_in-tree-client`). Confidence high.

## Goals / Non-Goals

**Goals:**
- Remove pin files and live “match PR #8” language.
- Keep published-module import ban.
- Point usage Language at the owned package.

**Non-Goals:**
- Runtime I/O changes.
- Rewriting archive OpenSpec folders.
- Deleting `knowledge/research/ext_simpleredis_client_pooled-mget/`.
- Relicensing or copyright headers in `.go` files.

## Decisions

1. **Delete the two pin files.** `LICENSE` is the same Apache-2.0 text as repo root and names no copyright holder. `SOURCE` duplicates Close/timeout facts already in code and spec.
2. **Edit live Purpose in `openspec/specs/core_cache_redis_in-tree-client/spec.md`.** OpenSpec ignores Purpose on a fold delta; the main spec Purpose must change in this change.
3. **Keep research extracts.** They remain facts about an outside repo at a historical pin. Update `knowledge/research/index_ext_simpleredis.md` description so it is not “this product relies on” that branch.
4. **Usage packet, not a new doc.** `knowledge/devdocs/core_cache_redis.md` already names the unit. Drop SOURCE from Key files and “copied from PR #8” from Language. Keep `_Avoid_: published github.com/maxlerebourg/simpleredis`.

## Risks / Trade-offs

- [Someone later treats maxlerebourg/simpleredis as the owner again] → Live spec forbids a match requirement; research stays historical-only.
- [Apache attribution worry] → Root `LICENSE` remains Apache-2.0.

## Migration Plan

No operator config change. Rollback is revert.
