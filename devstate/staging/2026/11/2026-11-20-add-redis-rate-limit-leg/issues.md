# Issues

- [ ] note large  `knowledge/debt/2026-11-20-extract-common-leg-abstraction.md`
  Why: each published leg is copied by hand into five places in `plugin.go` and `Bouncer`; the owner asked to suggest a shared leg unit before the next leg, and the Open-only rate-limit leg does not need it.
- [ ] note large  `knowledge/debt/2026-11-20-rate-limit-token-bucket-and-memory-store.md`
  Why: `tokenBucket`, `burst`, and the memory store are not in the first slice; the upstream blocker (utilities PR #54) is tagged in v1.0.9, which this branch now pins.
- [x] note large  `knowledge/debt/2026-11-20-bump-utilities-windowcounter-fixes.md`
  Why: `windowcounter` at v1.0.7 still has the stale-previous (PR #63) and EXPIRE-not-retried (PR #60) defects; bump when they are tagged.
  Closed 2026-11-21: utilities bumped to v1.0.9 (PRs #60, #62, #63); the buffered-outage contract change (#62) is handled (failure action now applies in exact mode only).
- [ ] note large  `knowledge/debt/2026-11-20-rate-limit-captcha-action.md`
  Why: a bucket `captcha` action would exempt every client holding a solved gate cookie; that exemption is the requirement's unanswered open decision 2.
- [ ] note large  `knowledge/debt/2026-11-20-rate-limit-ratelimit-response-headers.md`
  Why: the requirement lists `RateLimit-*` headers beside `Retry-After`; the IETF draft's header shape is unsettled, so this change sends `Retry-After` only (since utilities v1.0.10 the counter does return Limit, Remaining and Reset).
- [ ] note large  `knowledge/debt/2026-11-20-rate-limit-redis-backoff-gate.md`
  Why: in exact mode (`rateLimitSyncRate: 0`) a blackholed Redis costs each request the full 250ms rate-limit budget for the whole outage; no gate skips Redis after repeated failures. Buffered mode skips Redis for one sync rate after a failure (utilities v1.0.9).
- [ ] note large  `knowledge/debt/2026-11-21-single-reading-path-spec-names-bypassratelimit.md`
  Why: the live "Action-rule skips need a single-reading path" requirement omits `bypassRateLimit`, though the code and "Action rules fold every matching row" drop it on an ambiguous path too.
