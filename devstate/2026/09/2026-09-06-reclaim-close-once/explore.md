# Explore
IssueKey: 2026-09-06-reclaim-close-once

## Concepts
- **Incarnation lifetime (`life`)**: background context canceled on dispose; a goroutine started on first `Open` waits on it and is the documented Close owner for normal teardown.
- **Grace dispose (`fire`)**: deletes the slot, cancels `life`, and today also calls `closeFn` synchronously — duplicating the watcher.
- **Race-loser create**: extra `create()` on a lost first-Open race calls `closeFn` immediately; that is not incarnation dispose and must stay.
- **ResetForTest**: cancels `life` only; Close runs once via the watcher — the pattern to align `fire` with.

## Decisions
- Single Close owner = the `life` watcher goroutine started on first put (`pkg/reclaim/table.go:236-241`).
- `fire` (grace elapsed or zero-grace drop) shall cancel `life` and log dispose but not call `closeFn`.
- Race-loser path (`OpenWithGrace` extra create, lines 213-215) keeps immediate `closeFn` — orphan constructor, not slot incarnation end.
- Strengthen `TestTable_GraceClosesAfterSleep` (and add a concurrent fire-vs-watcher test) to assert exactly one Close per grace dispose.

## Open questions
- Q: Which single-owner design (`fire` vs watcher) fits all teardown paths without regressions?
  Decision: resolved — watcher-only Close; `fire` and `ResetForTest` cancel `life` only; race-loser keeps its own Close. Matches existing `ResetForTest` behavior and table comment at line 158.
  By: explore

- Q: Will removing `closeFn` from `fire` leave zero-grace dispose without Close?
  Decision: resolved — zero-grace `drop` calls `fire`, which cancels `life`; the watcher exits `waitCtx` and closes once.
  By: explore

- Q: Does concurrent cancel in `fire` vs watcher create a new race on non-idempotent closers?
  Decision: assumed — watcher alone calls `closeFn` after `life` ends; no concurrent double call. Test with atomic counter that fails on >1.
  By: explore
