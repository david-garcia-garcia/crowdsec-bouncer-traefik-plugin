# Test coverage

1. [judgement] Happy path only — `pkg/lapi/client_live.go:46` — spec scenario "IP ban stays on the IP key" (banned `?ip=` plus mapped Country ban) has no test that asserts the IP key holds the IP query result; `TestLiveLookup_IPSlotKeepsIPQueryResult` covers the clean-IP header-ban job
   → Assert IP-key payload is the IP ban (not the Country ban) after a dual-ban lookup, or skip if design's one dest-style test is enough
   Status: skipped
   Argument: judgement; design scoped one dest-style test; ticket job proven by TestLiveLookup_IPSlotKeepsIPQueryResult.
