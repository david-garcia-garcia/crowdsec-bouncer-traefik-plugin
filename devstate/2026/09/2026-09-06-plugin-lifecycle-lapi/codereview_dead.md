# Dead

1. [hard] Leftover production path — `pkg/reclaim/default.go:28` / `pkg/reclaim/table.go:156` — `Open` forwards to `OpenWithGrace` with table grace; `plugin.go` now opens via `crowdsecconnection.OpenStream` / `OpenLive` → `reclaim.OpenWithGrace` only (grep `reclaim\.Open` and non-test `\.Open(` on reclaim keys: zero production callers; only `pkg/reclaim/table_test.go` and the definitions)
   → Delete package `Open` and `(t *Table).Open`; retarget reclaim tests to `OpenWithGrace` with explicit grace
   Status: skipped
   Argument: `Open` is the specified public table API (`std_go_reclaim_context-lease` Open SHALL; usage `std_go_reclaim.md`). `OpenWithGrace` is the duration override the plugin uses. Deleting `Open` would miss the spec. Tests remain the table’s API callers.
