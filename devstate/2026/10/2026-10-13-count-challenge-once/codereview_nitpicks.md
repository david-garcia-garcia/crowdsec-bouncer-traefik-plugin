# Nitpicks

1. [hard] Linear coding — `pkg/httprule/action.go:114` — `Fold` inlines a lazily memoised path-ambiguity check (two flags `pathChecked`/`pathAmbiguous`) and the first-name record inside a three-deep nest in the row loop
   Fix: Extract one helper for "this row's path skips are dropped" (compute `SingleReadingPath` once, record `AmbiguousPathName`), and call it with a guard `continue` from the loop
   Status: done
   Argument: Extracted `pathReading.ambiguous()` (computes `SingleReadingPath` once per Fold); the loop now has one guard `if set.set.hasPath(i) && reading.ambiguous()` then `continue`.
