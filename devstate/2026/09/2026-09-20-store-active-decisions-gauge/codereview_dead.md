# Dead

1. [hard] Leftover production path — `pkg/decisionstore/store.go:280` — `func (s *Store) OriginID(name string) (uint16, bool)` only forwards to `s.origins.ID`; this change deleted the last production caller (`rememberActiveDecision`) and intern now runs in `memory.pack` / `(*redis).originID`. Grep `OriginID(` in `*.go`: definition plus `pkg/decisionstore/zzz_activecount_test.go` `originCount` only.
   → Delete `OriginID`; retarget `originCount` to range `ActiveCounts()` (Put already interns)
   Status: skipped
   Argument: dest already exported OriginID for intern; test helper still uses it; not a leftover this change invented.
