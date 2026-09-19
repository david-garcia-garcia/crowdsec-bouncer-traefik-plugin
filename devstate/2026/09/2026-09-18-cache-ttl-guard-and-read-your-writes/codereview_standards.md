# Standards

1. [judgement] Test-only pin-window override — `pkg/cache/cache.go:113-114` — `pinWindow` is a production field that only tests set (the comment says so)
   → Rename to `pinWindowForTest` if a later change touches the field; do not rename in this finish
   Status: skipped
   Argument: existing test seam from the apply; renaming is Bound the ask on a finish that must not restyle the neighborhood.
