# Issues

- [x] note large  `knowledge/debt/2026-11-20-extract-common-leg-abstraction.md`
  Why: each published leg is copied by hand into five places in `plugin.go` and `Bouncer`; the owner asked to suggest a shared leg unit before the next leg, and the Open-only rate-limit leg does not need it.
  Taken: change `share-rate-limit-leg-and-bucket-actions` group 1 (20c5ee77) moves LAPI, AppSec, captcha, and ModSec onto one `publishedLeg` table and one `legBinding`; group 2 (31ca4c93) adds the rate limit as the fifth entry.
- [ ] note large  `knowledge/debt/2026-11-20-rate-limit-token-bucket-and-memory-store.md`
  Why: `tokenBucket`, `burst`, and the memory store are not in the first slice; the upstream blocker (utilities PR #54) is tagged in v1.0.9, which this branch now pins.
- [x] note large  `knowledge/debt/2026-11-20-bump-utilities-windowcounter-fixes.md`
  Why: `windowcounter` at v1.0.7 still has the stale-previous (PR #63) and EXPIRE-not-retried (PR #60) defects; bump when they are tagged.
  Closed 2026-11-21: utilities bumped to v1.0.9 (PRs #60, #62, #63); the buffered-outage contract change (#62) is handled (failure action now applies in exact mode only).
- [x] note large  `knowledge/debt/2026-11-20-rate-limit-captcha-action.md`
  Why: a bucket `captcha` action would exempt every client holding a solved gate cookie; that exemption is the requirement's unanswered open decision 2.
  Taken: change `share-rate-limit-leg-and-bucket-actions` group 3 (f5dd22a4) adds `action: captcha` with the solved-client exemption the human accepted (decision 4); 36f02da8 lets the challenge form solve it on routers without AppSec.
- [ ] note large  `knowledge/debt/2026-11-20-rate-limit-ratelimit-response-headers.md`
  Why: the requirement lists `RateLimit-*` headers beside `Retry-After`; the IETF draft's header shape is unsettled, so this change sends `Retry-After` only (since utilities v1.0.10 the counter does return Limit, Remaining and Reset).
- [ ] note large  `knowledge/debt/2026-11-20-rate-limit-redis-backoff-gate.md`
  Why: in exact mode (`rateLimitSyncRate: 0`) a blackholed Redis costs each request the full 250ms rate-limit budget for the whole outage; no gate skips Redis after repeated failures. Buffered mode skips Redis for one sync rate after a failure (utilities v1.0.9).
- [ ] note large  `knowledge/debt/2026-11-21-single-reading-path-spec-names-bypassratelimit.md`
  Why: the live "Action-rule skips need a single-reading path" requirement omits `bypassRateLimit`, though the code and "Action rules fold every matching row" drop it on an ambiguous path too.
- [ ] note large  `knowledge/debt/2026-11-21-rate-limit-captcha-marker-flood.md`
  Why: the captcha page's own requests skip every rate-limit bucket (human decision 5), so a client that always sends the challenge marker is never charged and each marker POST costs a siteverify call.
- [ ] note large  `knowledge/debt/2026-11-21-instance-slots-replace-trace-scenario.md`
  Why: the live instance-slots scenario "Replace A by B logs two bound lines" says no unbound line between them; the code logs unbound for A first, and the leg extraction pins the code.
- [x] note large  `knowledge/debt/2026-11-21-rate-limit-marker-post-uncharged-without-gate.md`
  Why: a POST carrying the challenge marker skips every rate-limit bucket even when no captcha gate answers it (policy without a captcha answer and no AppSec, or a `bypassCaptcha` rule), so it reaches the application uncharged.
  Taken: human decision 2026-11-22 ("Cobrarlo"); e4e19906 skips the buckets only when `isRateLimitChallengeFormAnswer` holds (usable captcha, captcha-answering policy, no `bypassCaptcha`, then the marker) and charges every other marker POST; the cheap checks run before the body peek (Performance 1).
- [x] note large  `knowledge/debt/2026-11-21-rate-limit-unpublished-owner-warn.md`
  Why: a subscriber whose rate-limit owner is not published passes every request with only a TRACE unbound line, so a typo or a removed owner silently disables the limit.
  Taken: human decision 2026-11-22 ("WARN al desconectarse"); dcfd0393 logs WARN `crowdsec bouncer rate limit owner unavailable` once per move to no client and INFO `crowdsec bouncer rate limit owner available` on the bind that ends it, from the rate-limit binding's unbind and bind hooks, never per request.
