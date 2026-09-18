# Test coverage

1. [hard] Critical path untested — `pkg/bouncer/bouncer.go:215` / `pkg/bouncer/bouncer.go:283` — packed drop must resolve `table[id]` (or leftover suffix) before `IncDropped`; `TestPackedDropSendsOrigin` calls `OriginName` then `IncDropped` itself, and `TestServeHTTP_PackedMemoryBanRemediates` only asserts 403
   → Assert ServeHTTP (or `resolveStoredOrigin`) on a packed interned ban posts `dropped` with `origin=crowdsec`
   Status: done
   Argument: f7bd466 added `TestServeHTTP_PackedMemoryBanResolvesDroppedOrigin` (ServeHTTP 403 plus `resolveStoredOrigin` on interned packed ban).
2. [hard] Edge case untested — `pkg/lapi/origindict.go:31` / `pkg/lapi/decisionstore.go:76` — empty origin must not consume an id and must stay leftover; `(none)`
   → Assert `InternOrigin("")` is not interned and `RemediationStored` with empty origin stays letter-only
   Status: done
   Argument: f7bd466 added `TestInternOriginEmptyIsNotInterned` and `TestRemediationStoredEmptyOriginStaysLetterOnly`.
3. [hard] Edge case untested — `pkg/lapi/client_metrics.go:216` — overflow slot must keep leftover origin text and POST today's labels; `TestOriginOverflowStaysOnStringPathAndLogsOnce` only covers `RemediationStored`, `TestEmptyOriginSlotKeepsTodayLabels` only covers empty
   → After filling 65535 names, `rememberActiveDecision` a new origin and assert `active_decisions` still has that origin label
   Status: done
   Argument: f7bd466 added `TestOriginOverflowActiveDecisionKeepsOriginLabel`.
4. [judgement] Happy path only — `pkg/lapi/client_metrics.go:239` — `familyByte`/`familyLabel` ipv6 arm untested; compact-slot tests use `1.2.3.4` → `ipv4` only
   → Assert a `2001:db8::1` slot POSTs `ip_type=ipv6`, or skip if unreachable
   Status: skipped
   Argument: judgement; ipv6 compact-slot label is not a hard coverage gap this change owns.
