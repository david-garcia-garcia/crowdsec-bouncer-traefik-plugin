# Performance

none.

One uncontended mutex acquire per captured log record, in tests only. `Close()` inside two tests replaces work that `t.Cleanup(reclaim.ResetForTest)` did a moment later, so the package runtime is unchanged (`ok pkg/lapi 7.4-7.9s` before and after).
