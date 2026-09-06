# Standards

1. [hard] Name for the scope — `pkg/crowdsecconnection/session.go:297` — `streamConn` names a stream-only job but `OpenLive` is a caller; the body only type-asserts reclaim storage to `*CrowdsecConnection`
   → Rename to the job both paths use (e.g. `crowdsecConnectionFromStored`) and drop the stream stem from the return local
   Status: done
   Argument: renamed to `connectionFromStored`; return local `conn` (122e06b).

2. [hard] Name for the scope — `pkg/crowdsecconnection/session.go:261` — `typedErr` names how the error was produced, not the role in `OpenStream`
   → Use `err` or `connErr`
   Status: done
   Argument: `connErr` (122e06b).

3. [hard] Name for the scope — `pkg/crowdsecconnection/session.go:284` — literal `"live"` is a placeholder middleware label in reclaim assert errors; `plugin.go` already has `name` but does not pass it to `OpenLive`
   → Thread `middlewareName` through `OpenLive` and into the assert helper
   Status: done
   Argument: `OpenLive(..., middlewareName, pluginVersion)`; `plugin.go` passes `name` (122e06b).

4. [hard] Leave a trail — `pkg/crowdsecconnection/session.go:287` — new `wrappedConnection` has no job comment
   → Add one line: build `*reclaim.Wrapped` so Yaegi can Sleep/Wake/Close without foreign interface asserts
   Status: done
   Argument: job comment on `wrappedConnection` (122e06b).

5. [hard] Leave a trail — `pkg/reclaim/table.go:124` — new `unwrap`, `sleeperFuncs`, and `closerFunc` have no job comments
   → Add succinct comments on each helper’s contract (Wrapped vs same-package sleeper/closer)
   Status: done
   Argument: comments on `unwrap`, `sleeperFuncs`, `closerFunc` (122e06b).

6. [judgement] Mysterious Name — `pkg/crowdsecconnection/session.go:256` — `sleeper := reclaim.Peek(bindKey)` is a `View` that may be live or sleeping, not a sleeper value
   → Rename to `priorSlot` or `peekBeforeOpen`
   Status: skipped
   Argument: judgement; Peek-before-Open is still used to take sleeper ownership; rename is optional.

7. [judgement] Mysterious Name — `pkg/crowdsecconnection/session.go:200` — `jsonObject` hides that it flattens `streamSettings` for field-name diffing
   → Rename to `settingsFieldMap` (or similar)
   Status: skipped
   Argument: judgement; local helper, JSON object map is accurate enough.

8. [judgement] Duplicated Code — `pkg/crowdsecconnection/session_test.go:451` and `plugin_test.go:532` — `waitStreamSessionInGrace` and `waitPluginStreamInGrace` repeat the same Peek-until-sleeping loop
   → Extract one test helper in a shared test package or have one call the other
   Status: skipped
   Argument: judgement; two packages, extracting a shared test pkg is outside this apply.
