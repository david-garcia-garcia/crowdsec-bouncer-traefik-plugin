# Performance

1. [hard] I/O in a loop — `pkg/decisionscope/lookup.go:114` — allow-path `GetMany(keys)` then `GetInt` per key; Redis `getInt` is one `Get` (`pkg/cache/cache.go:171`); `PackMemory` skips Redis so those GETs cannot hit remediations; memory `GetMany` misses `uint32` and walks the same keys again (ttl_map lock twice); grows with request rate × lookup keys (IP + present header scopes)
   → GetInt first and Get/GetMany only on miss, or skip the GetInt loop on Redis leftover
   Status: done
   Argument: 4d358dce GetInt first; GetMany only leftover keys.
2. [judgement] Quadratic work on a growing set — `pkg/lapi/decisionstore.go:108` — `lookupIntern` full-scans `internNames` on every `Intern`; stream apply calls `Intern` twice per decision (`PackMemory` + `rememberActiveDecision`); unique `lists:<scenario>` cardinality is unknown and does not grow with IP count; table cap 65535
   → Index names with a `map[string]uint16` beside the snapshot slice
   Status: skipped
   Argument: judgement; unique origin names do not grow with IP count.
