# Test coverage

1. [judgement] Non-origin-form path untested — `pkg/httprule/path.go:23` — the `!strings.HasPrefix(requestPath, "/")` branch (empty path from an absolute-form target, `*` from `OPTIONS *`) is special-cased but `TestSingleReadingPath` only feeds origin-form paths and nil
   Fix: Add `SingleReadingPath` cases for an empty `Path` and `*` that expect false, or drop the branch if unreachable
   Status: done
   Argument: `TestSingleReadingPath` now checks targets with no leading `/`: empty path, `*`, and an authority-only CONNECT target, all false.
