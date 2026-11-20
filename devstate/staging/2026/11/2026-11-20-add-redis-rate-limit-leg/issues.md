# Issues

- [ ] note large  `knowledge/debt/2026-11-20-extract-common-leg-abstraction.md`
  Why: each published leg is copied by hand into five places in `plugin.go` and `Bouncer`; the owner asked to suggest a shared leg unit before the next leg, and the Open-only rate-limit leg does not need it.
- [ ] note large  `knowledge/debt/2026-11-20-rate-limit-token-bucket-and-memory-store.md`
  Why: utilities `tokenbucket` at v1.0.7 over-admits under flood (PR #54 open, in no tag), so `tokenBucket`, `burst`, and the memory store wait for an upstream tag.
- [ ] note large  `knowledge/debt/2026-11-20-bump-utilities-windowcounter-fixes.md`
  Why: `windowcounter` at v1.0.7 still has the stale-previous (PR #63) and EXPIRE-not-retried (PR #60) defects; bump when they are tagged.
- [ ] note large  `knowledge/debt/2026-11-20-rate-limit-captcha-action.md`
  Why: a bucket `captcha` action would exempt every client holding a solved gate cookie; that exemption is the requirement's unanswered open decision 2.
- [ ] note large  `knowledge/debt/2026-11-20-rate-limit-ratelimit-response-headers.md`
  Why: the requirement lists `RateLimit-*` headers beside `Retry-After`; the IETF draft's header shape is unsettled and windowcounter has no remaining count, so this change sends `Retry-After` only.
- [ ] note large  `knowledge/debt/2026-11-20-rate-limit-redis-backoff-gate.md`
  Why: a blackholed Redis costs each request the full 250ms rate-limit budget for the whole outage; no gate skips Redis after repeated failures.
