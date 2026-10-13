# Code review — Dead
Pin: origin/master...HEAD

## Findings

- [noted] `decisionscope.AddRange` and `decisionscope.RemoveRange` have no production caller — only
  tests in `pkg/decisionscope` and `pkg/lapi`. The apply makes them discard a real error with `_ =`.
  Argument: deleting them rewrites about a dozen test call sites across two packages in a change
  whose product diff is five files. Recorded as `issues.md` note plus
  `knowledge/debt/2026-09-18-decisionscope-addrange-test-only-wrappers.md`.

- [resolved] PR #34's `IPLookupCacheKey` had a "prefer `IPCacheKey(remoteIP)` when it differs from
  the trimmed raw string" branch. That branch only existed because `IPCacheKey` could not canonicalize
  bare addresses; fixing `IPCacheKey` makes it unreachable, so it is not carried over.

- [resolved] `deleteStreamDecision` still deletes the verbatim `item.Value` alongside the canonical
  slot. That is not dead: it is the cleanup path for entries written under the old spelling, and it
  costs one `DEL` on a path that already issues one.
