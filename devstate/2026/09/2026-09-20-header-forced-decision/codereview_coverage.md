# Test coverage

1. [hard] Edge case untested — `pkg/bouncer/bouncer.go:152` — `forcedDecisionKind` `TrimSpace`s the request header value before matching exact `b`/`c` (proposal/spec: exact trimmed tokens); `TestServeHTTP_forcedDecisionCaptchaSkipsStreamBan` and `TestServeHTTP_forcedDecisionBanSkipsStream` send exact `c`/`b`, unknown-token table uses `" "` as a miss — `(none)` fails if that `TrimSpace` is reverted
   → Assert padded ` c ` (or ` b `) still remediates without lookup
   Status: done
   Argument: TestServeHTTP_forcedDecisionTrimmedHeaderValues asserts padded ` c ` and ` b `; 98115d9f.
